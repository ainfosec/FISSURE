/* -*- c++ -*- */
/* 
 * Copyright 2015 Felix Wunsch, Communications Engineering Lab (CEL) / Karlsruhe Institute of Technology (KIT) <wunsch.felix@googlemail.com>.
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
#include "frame_buffer_cc_impl.h"

namespace gr {
  namespace ieee802_15_4 {

    frame_buffer_cc::sptr
    frame_buffer_cc::make(int nsym_frame)
    {
      return gnuradio::get_initial_sptr
        (new frame_buffer_cc_impl(nsym_frame));
    }

    /*
     * The private constructor
     */
    frame_buffer_cc_impl::frame_buffer_cc_impl(int nsym_frame)
      : gr::block("frame_buffer_cc",
              gr::io_signature::make(1, 1, sizeof(gr_complex)),
              gr::io_signature::make(1, 1, sizeof(gr_complex))),
      d_nsym_frame(nsym_frame)
    {
      d_buf.clear();
      set_output_multiple(d_nsym_frame);
      set_tag_propagation_policy(TPP_DONT);
    }

    /*
     * Our virtual destructor.
     */
    frame_buffer_cc_impl::~frame_buffer_cc_impl()
    {
    }

    void
    frame_buffer_cc_impl::forecast (int noutput_items, gr_vector_int &ninput_items_required)
    {
        ninput_items_required[0] = 3*d_nsym_frame;
    }

    int
    frame_buffer_cc_impl::general_work (int noutput_items,
                       gr_vector_int &ninput_items,
                       gr_vector_const_void_star &input_items,
                       gr_vector_void_star &output_items)
    {
        const gr_complex *in = (const gr_complex *) input_items[0];
        gr_complex *out = (gr_complex *) output_items[0];

        int samples_consumed = 0;
        int samples_produced = 0;

        std::vector<tag_t> tags;
        get_tags_in_range(tags, 0, nitems_read(0), nitems_read(0) + ninput_items[0], pmt::string_to_symbol("SOF"));

        // NOTE: This algorithm causes a delay of one frame length. Considering that packets may arrive infrequently, this could be an issue
        if(tags.size() >= 2)
        {
          uint64_t first_tag_pos = tags[0].offset - nitems_read(0);
          uint64_t second_tag_pos = tags[1].offset - nitems_read(0);
          // std::cout << "Frame buffer: found SOF tags at pos " << tags[0].offset << " and " << tags[1].offset << std::endl;
          if(first_tag_pos==second_tag_pos)
            throw std::runtime_error("Frame Buffer: Two SOF tags at same position");          // std::cout << "Frame buffer: Consume " << first_tag_pos << " samples." << std::endl;
          samples_consumed += first_tag_pos;
          if(second_tag_pos - first_tag_pos < d_nsym_frame)
          {
            // std::cout << "Frame buffer: Incomplete frame detected, drop " << second_tag_pos - first_tag_pos << " symbols." << std::endl;
            samples_consumed += second_tag_pos - first_tag_pos;
          }
          else if(ninput_items[0] - samples_consumed >= d_nsym_frame)
          {
            // std::cout << "Frame buffer: Return frame of " << d_nsym_frame << " samples" << std::endl;
            // for(int i=0; i<d_nsym_frame; i++)
            //   std::cout << *(in+samples_consumed+i) << ", ";
            // std::cout << std::endl;
            memcpy(out, in+samples_consumed, sizeof(gr_complex)*d_nsym_frame);
            samples_consumed += d_nsym_frame;
            samples_produced += d_nsym_frame;
          }
        }
        else // if there are no two tags in range, consume samples up to the next tag or all samples if no tags are present
        {
          if(tags.size() == 1)
            samples_consumed += tags[0].offset - nitems_read(0);
          else
          {
            samples_consumed += ninput_items[0];
            // std::cout << "Frame buffer: No tags found, consume input buffer" << std::endl;
          }
        }

        consume_each (samples_consumed);
        return samples_produced;
    }

  } /* namespace ieee802_15_4 */
} /* namespace gr */

