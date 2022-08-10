/* -*- c++ -*- */
/*
 * @file
 * @author (C) 2014 by Piotr Krysik <ptrkrysik@gmail.com>
 * @section LICENSE
 *
 * Gr-gsm is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3, or (at your option)
 * any later version.
 *
 * Gr-gsm is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with gr-gsm; see the file COPYING.  If not, write to
 * the Free Software Foundation, Inc., 51 Franklin Street,
 * Boston, MA 02110-1301, USA.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <gnuradio/io_signature.h>
#include "controlled_rotator_cc_impl.h"

namespace gr {
  namespace gsm {

    controlled_rotator_cc::sptr
    controlled_rotator_cc::make(double phase_inc)
    {
      return gnuradio::get_initial_sptr
        (new controlled_rotator_cc_impl(phase_inc));
    }

    /*
     * The private constructor
     */
    controlled_rotator_cc_impl::controlled_rotator_cc_impl(double phase_inc)
      : gr::sync_block("controlled_rotator_cc",
              gr::io_signature::make2(1, 2, sizeof(gr_complex), sizeof(float)),
              gr::io_signature::make(1, 1, sizeof(gr_complex)))
    {
      set_phase_inc(phase_inc);
    }
    
    /*
     * Our virtual destructor.
     */
    controlled_rotator_cc_impl::~controlled_rotator_cc_impl()
    {
    }

    void
    controlled_rotator_cc_impl::set_phase_inc(double phase_inc)
    {
      d_phase_inc = phase_inc;
      d_r.set_phase_incr( exp(gr_complex(0, (double)phase_inc)) );
    }

//    void
//    controlled_rotator_cc_impl::set_samp_rate(double samp_rate)
//    {
//      d_samp_rate = samp_rate;
//    }

    int
    controlled_rotator_cc_impl::work(int noutput_items,
			  gr_vector_const_void_star &input_items,
			  gr_vector_void_star &output_items)
		{
		  //process phase_inc input
      /*if(input_items.size() == 2) {
        int ii=0;
        const float *pp = (const float *)input_items[1];
        
        while(ii < noutput_items){
          //look for different values on phase increment control input
          if(d_phase_inc != (*pp)){

            set_phase_inc(*(pp));      //set new value of phase increment
            
            float freq_offset_setting = (*(pp) / (2*M_PI)) * d_samp_rate; //send stream tag with a new value of the frequency offset

            uint64_t offset = nitems_written(0);
            pmt::pmt_t key = pmt::string_to_symbol("setting_freq_offset");
            pmt::pmt_t value =  pmt::from_double(freq_offset_setting);
            add_item_tag(0,offset, key, value);
    
            break;
          }
          pp++;
          ii++;
        }
      }
      */
      	
      //get complex input and output
      const gr_complex *in = (const gr_complex *)input_items[0];
      gr_complex *out = (gr_complex *)output_items[0];
		  //get tags

      uint64_t processed_in = 0;
      uint64_t produced_out = 0;

      std::vector<tag_t> set_phase_inc_tags;

      pmt::pmt_t key = pmt::string_to_symbol("set_phase_inc");
      get_tags_in_window(set_phase_inc_tags, 0, 0, noutput_items, key);
      
      for(std::vector<tag_t>::iterator i_tag = set_phase_inc_tags.begin(); i_tag < set_phase_inc_tags.end(); i_tag++){
        uint64_t tag_offset_rel = i_tag->offset-nitems_read(0);
        set_phase_inc(pmt::to_double(i_tag->value));
        uint64_t samples_to_process = tag_offset_rel-processed_in;
        d_r.rotateN((out+produced_out), const_cast<gr_complex *>(in+processed_in), samples_to_process);
        processed_in = processed_in + samples_to_process;
        produced_out = produced_out + samples_to_process;
//        std::cout << "Rotator, phase inc: " << pmt::to_double(i_tag->value) << std::endl;
//        
//        float freq_offset_setting = (pmt::to_double(i_tag->value) / (2*M_PI)) * d_samp_rate; //send stream tag with a new value of the frequency offset
//        pmt::pmt_t key = pmt::string_to_symbol("setting_freq_offset");
//        pmt::pmt_t value =  pmt::from_double(freq_offset_setting);
//        add_item_tag(0,i_tag->offset, key, value);
      }
      
      d_r.rotateN((out+produced_out), const_cast<gr_complex *>(in+processed_in), (noutput_items-produced_out)); //const_cast<gr_complex *> is workaround old implementation of rotateN that is still present in ubuntu 14.04 packages
      return noutput_items;
		}
  } /* namespace gsm */
} /* namespace gr */

