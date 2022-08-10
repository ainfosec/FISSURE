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

#ifndef INCLUDED_GSM_MESSAGE_SOURCE_IMPL_H
#define INCLUDED_GSM_MESSAGE_SOURCE_IMPL_H

#include <grgsm/qa_utils/message_source.h>

namespace gr {
  namespace gsm {

    class message_source_impl : public message_source
    {
     private:
        boost::shared_ptr<gr::thread::thread> d_thread;
        std::vector<std::vector<uint8_t> > d_msgs;
        bool d_finished;
        void run();
     public:
      message_source_impl(const std::vector<std::string> &msg_data);
      ~message_source_impl();
      virtual void set_msg_data(const std::vector<std::string> &msg_data);
      bool start();
      bool stop();
      bool finished();
    };

  } // namespace grgsm
} // namespace gr

#endif /* INCLUDED_GSM_MESSAGE_SOURCE_IMPL_H */

