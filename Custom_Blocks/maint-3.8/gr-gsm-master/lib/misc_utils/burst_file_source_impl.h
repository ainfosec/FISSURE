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

#ifndef INCLUDED_GSM_BURST_FILE_SOURCE_IMPL_H
#define INCLUDED_GSM_BURST_FILE_SOURCE_IMPL_H

#include <grgsm/misc_utils/burst_file_source.h>
#include <fstream>

namespace gr {
  namespace gsm {

    class burst_file_source_impl : public burst_file_source
    {
     private:
        boost::shared_ptr<gr::thread::thread> d_thread;
        std::ifstream d_input_file;
        bool d_finished;
        void run();
     public:
        burst_file_source_impl(const std::string &filename);
        ~burst_file_source_impl();
        bool start();
        bool stop();
        bool finished();
    };
  } // namespace gsm
} // namespace gr

#endif /* INCLUDED_GSM_BURST_FILE_SOURCE_IMPL_H */

