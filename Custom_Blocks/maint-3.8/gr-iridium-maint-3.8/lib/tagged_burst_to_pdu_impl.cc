/* -*- c++ -*- */
/*
 * Copyright 2020 Free Software Foundation, Inc.
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
#include "tagged_burst_to_pdu_impl.h"

#include <volk/volk.h>

#include <unistd.h>
#include <inttypes.h>

namespace gr {
  namespace iridium {

    tagged_burst_to_pdu::sptr
    tagged_burst_to_pdu::make(int max_burst_size, float relative_center_frequency,
                                float relative_span, float relative_sample_rate,
                                double sample_offset,
                                int outstanding_limit, bool drop_overflow)
    {
      return gnuradio::get_initial_sptr
        (new tagged_burst_to_pdu_impl(max_burst_size, relative_center_frequency,
            relative_span, relative_sample_rate,
            sample_offset,
            outstanding_limit, drop_overflow));
    }


    /*
     * The private constructor
     */
    tagged_burst_to_pdu_impl::tagged_burst_to_pdu_impl(int max_burst_size, float relative_center_frequency,
                                                        float relative_span, float relative_sample_rate,
                                                        double sample_offset,
                                                        int outstanding_limit, bool drop_overflow)
      : gr::sync_block("tagged_burst_to_pdu",
              gr::io_signature::make(1, 1, sizeof(gr_complex)),
              gr::io_signature::make(0, 0, 0)),
              d_debug(false),
              d_relative_center_frequency(relative_center_frequency),
              d_relative_span(relative_span),
              d_relative_sample_rate(relative_sample_rate),
              d_sample_offset(sample_offset),
              d_max_burst_size(max_burst_size),
              d_outstanding(0),
              d_max_outstanding(0),
              d_outstanding_limit(outstanding_limit),
              d_n_dropped_bursts(0),
              d_drop_overflow(drop_overflow),
              d_blocked(false)
    {
      d_lower_border = relative_center_frequency - relative_span / 2;
      d_upper_border = relative_center_frequency + relative_span / 2;
      message_port_register_out(pmt::mp("cpdus"));

      message_port_register_in(pmt::mp("burst_handled"));
      set_msg_handler(pmt::mp("burst_handled"), [this](pmt::pmt_t msg) { this->burst_handled(msg); });
    }

    /*
     * Our virtual destructor.
     */
    tagged_burst_to_pdu_impl::~tagged_burst_to_pdu_impl()
    {
    }

    void
    tagged_burst_to_pdu_impl::burst_handled(pmt::pmt_t msg)
    {
      d_outstanding--;
    }

    void
    tagged_burst_to_pdu_impl::append_to_burst(burst_data &burst, const gr_complex * data, size_t n)
    {
        // If the burst really gets longer than this, we can just throw away the data
      if(burst.len + n <= d_max_burst_size) {
        volk_32fc_s32fc_x2_rotator_32fc(burst.data + burst.len, data, burst.phase_incr, &burst.phase, n);
        burst.len += n;
      }
    }

    void
    tagged_burst_to_pdu_impl::publish_burst(burst_data &burst)
    {
      pmt::pmt_t d_pdu_meta = pmt::make_dict();
      pmt::pmt_t d_pdu_vector = pmt::init_c32vector(burst.len, burst.data);

      d_pdu_meta = pmt::dict_add(d_pdu_meta, pmt::mp("id"), pmt::mp(burst.id));
      d_pdu_meta = pmt::dict_add(d_pdu_meta, pmt::mp("magnitude"), pmt::mp(burst.magnitude));
      d_pdu_meta = pmt::dict_add(d_pdu_meta, pmt::mp("center_frequency"), pmt::mp(burst.center_frequency));
      d_pdu_meta = pmt::dict_add(d_pdu_meta, pmt::mp("sample_rate"), pmt::mp(burst.sample_rate));
      d_pdu_meta = pmt::dict_add(d_pdu_meta, pmt::mp("timestamp"), pmt::mp(burst.timestamp));
      d_pdu_meta = pmt::dict_add(d_pdu_meta, pmt::mp("noise"), pmt::mp(burst.noise));

      pmt::pmt_t msg = pmt::cons(d_pdu_meta,
          d_pdu_vector);

      d_outstanding++;
      if(d_outstanding >= d_outstanding_limit) {
        d_blocked = true;
      }

      if(d_outstanding > d_max_outstanding) {
        d_max_outstanding = d_outstanding;
      }

      message_port_pub(pmt::mp("cpdus"), msg);
    }

    void
    tagged_burst_to_pdu_impl::create_new_bursts(int noutput_items,
            const gr_complex * in)
    {
      std::vector<tag_t> new_bursts;
      get_tags_in_window(new_bursts, 0, 0, noutput_items, pmt::mp("new_burst"));

      for(tag_t tag : new_bursts) {
        float relative_frequency = pmt::to_float(pmt::dict_ref(tag.value, pmt::mp("relative_frequency"), pmt::PMT_NIL));

        if(d_lower_border < relative_frequency && relative_frequency <= d_upper_border) {
          uint64_t id = pmt::to_uint64(pmt::dict_ref(tag.value, pmt::mp("id"), pmt::PMT_NIL));
          float magnitude = pmt::to_float(pmt::dict_ref(tag.value, pmt::mp("magnitude"), pmt::PMT_NIL));
          float center_frequency = pmt::to_float(pmt::dict_ref(tag.value, pmt::mp("center_frequency"), pmt::PMT_NIL));
          float sample_rate = pmt::to_float(pmt::dict_ref(tag.value, pmt::mp("sample_rate"), pmt::PMT_NIL));
          float relative_frequency = pmt::to_float(pmt::dict_ref(tag.value, pmt::mp("relative_frequency"), pmt::PMT_NIL));
          uint64_t timestamp = pmt::to_uint64(pmt::dict_ref(tag.value, pmt::mp("timestamp"), pmt::PMT_NIL));
          float noise = pmt::to_float(pmt::dict_ref(tag.value, pmt::mp("noise"), pmt::PMT_NIL));


          // Adjust the values based on our position behind a potential filter bank
          center_frequency += d_relative_center_frequency * sample_rate;
          sample_rate = sample_rate * d_relative_sample_rate;
          relative_frequency = (relative_frequency - d_relative_center_frequency) / d_relative_sample_rate;
          center_frequency += relative_frequency * sample_rate;

          timestamp += d_sample_offset * 1e9 / sample_rate;

          burst_data burst = {id, (double)tag.offset, magnitude,
            center_frequency, sample_rate, timestamp, noise, 0};
          burst.data = (gr_complex *) volk_malloc(sizeof(gr_complex) * d_max_burst_size, volk_get_alignment());

          float phase_inc = 2 * M_PI * -relative_frequency;
          burst.phase_incr = exp(gr_complex(0, phase_inc));
          burst.phase = gr_complex(1, 0);

          if(burst.data != NULL) {
            d_bursts[id] = burst;
            int relative_offset = burst.offset - nitems_read(0);
            int to_copy = noutput_items - relative_offset;
            append_to_burst(d_bursts[id], &in[relative_offset], to_copy);
            if(d_debug) {
              printf("New burst: offset=%" PRIu64 ", id=%" PRIu64 ", relative_frequency=%f, magnitude=%f\n", tag.offset, id, relative_frequency, magnitude);
            }
          } else {
            printf("Error, malloc failed\n");
          }
        }
      }
    }

    void
    tagged_burst_to_pdu_impl::publish_and_remove_old_bursts(int noutput_items, const gr_complex * in)
    {
      std::vector<tag_t> gone_bursts;
      get_tags_in_window(gone_bursts, 0, 0, noutput_items, pmt::mp("gone_burst"));

      for(tag_t tag : gone_bursts) {
        uint64_t id = pmt::to_uint64(pmt::dict_ref(tag.value, pmt::mp("id"), pmt::PMT_NIL));

        if(d_bursts.count(id)) {
          burst_data &burst = d_bursts[id];
          int relative_offset = tag.offset - nitems_read(0);
          append_to_burst(burst, in, relative_offset);
          if(d_debug) {
            printf("gone burst: %" PRIu64 " %zu\n", id, burst.len);
          }
          publish_burst(burst);
          volk_free(d_bursts[id].data);
          d_bursts.erase(id);
        }
      }
    }

    void
    tagged_burst_to_pdu_impl::update_current_bursts(int noutput_items, const gr_complex * in)
    {
      for(auto& kv : d_bursts) {
        append_to_burst(kv.second, in, noutput_items);
      }
    }

    uint64_t
    tagged_burst_to_pdu_impl::get_n_dropped_bursts()
    {
      return d_n_dropped_bursts;
    }

    int
    tagged_burst_to_pdu_impl::get_output_queue_size()
    {
        return d_outstanding;
    }

    int
    tagged_burst_to_pdu_impl::get_output_max_queue_size()
    {
        int tmp = d_max_outstanding;
        d_max_outstanding = 0;
        return tmp;
    }

    int
    tagged_burst_to_pdu_impl::work(int noutput_items,
        gr_vector_const_void_star &input_items,
        gr_vector_void_star &output_items)
    {
      const gr_complex *in = (const gr_complex *) input_items[0];

      if(d_outstanding_limit && d_blocked && d_outstanding > d_outstanding_limit / 2) {
        if(d_drop_overflow) {
          uint64_t n_dropped_bursts = 0;

          auto b = std::begin(d_bursts);

          while (b != std::end(d_bursts)) {
            n_dropped_bursts++;
            volk_free(b->second.data);
            b = d_bursts.erase(b);
          }

          std::vector<tag_t> new_bursts;
          get_tags_in_window(new_bursts, 0, 0, noutput_items, pmt::mp("new_burst"));
          n_dropped_bursts += new_bursts.size();

          //fprintf(stderr, "tagged_burst_to_pdu: Queue full. Dropped %d samples. Dropped %" PRIu64 " bursts.\n", noutput_items, n_dropped_bursts);
          if(n_dropped_bursts) {
            fprintf(stderr, "tagged_burst_to_pdu: Queue full. Dropped %" PRIu64 " bursts.\n", n_dropped_bursts);
          }
          d_n_dropped_bursts += n_dropped_bursts;
          return noutput_items;
        } else {
          // Sleep a bit until our bursts have been processed
          usleep(100000);

          // Tell the scheduler that we have not consumed any input
          return 0;
        }
      }

      d_blocked = false;

      publish_and_remove_old_bursts(noutput_items, in);
      update_current_bursts(noutput_items, in);
      create_new_bursts(noutput_items, in);

      // Not sure if this makes sense in a sink block
      return noutput_items;
    }

  } /* namespace iridium */
} /* namespace gr */

