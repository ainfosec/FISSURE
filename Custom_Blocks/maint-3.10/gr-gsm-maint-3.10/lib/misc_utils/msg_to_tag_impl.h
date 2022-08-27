/* -*- c++ -*- */
/* @file
 * @author (C) 2016 by Piotr Krysik <ptrkrysik@gmail.com>
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
 * 
 */

#ifndef INCLUDED_GSM_MSG_TO_TAG_IMPL_H
#define INCLUDED_GSM_MSG_TO_TAG_IMPL_H

#include <gsm/misc_utils/msg_to_tag.h>

namespace gr {
  namespace gsm {

    class msg_to_tag_impl : public msg_to_tag
    {
     private:
        std::deque<pmt::pmt_t> d_msg_queue;

     public:
      msg_to_tag_impl();
      ~msg_to_tag_impl();
      void queue_msg(pmt::pmt_t msg);

      // Where all the action really happens
      int work(int noutput_items,
         gr_vector_const_void_star &input_items,
         gr_vector_void_star &output_items);
    };

  } // namespace gsm
} // namespace gr

#endif /* INCLUDED_GSM_MSG_TO_TAG_IMPL_H */

