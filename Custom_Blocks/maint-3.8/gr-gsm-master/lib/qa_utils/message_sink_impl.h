/* -*- c++ -*- */
/* @file
 * @author (C) 2015 by Roman Khassraf <rkhassraf@gmail.com>
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

#ifndef INCLUDED_GSM_MESSAGE_SINK_IMPL_H
#define INCLUDED_GSM_MESSAGE_SINK_IMPL_H

#include <grgsm/qa_utils/message_sink.h>

namespace gr {
  namespace gsm {

    class message_sink_impl : public message_sink
    {
     private:
      std::vector<std::string> d_messages;

     public:
      message_sink_impl();
      ~message_sink_impl();
      void process_message(pmt::pmt_t msg);
      virtual std::vector<std::string> get_messages();
    };

  } // namespace gsm
} // namespace gr

#endif /* INCLUDED_GSM_MESSAGE_SINK_IMPL_H */

