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

#ifndef INCLUDED_GSM_BURST_SOURCE_IMPL_H
#define INCLUDED_GSM_BURST_SOURCE_IMPL_H

#define BURST_SIZE  148

#include <gsm/qa_utils/burst_source.h>
#include <fstream>


namespace gr {
  namespace gsm {

    class burst_source_impl : public burst_source
    {
     private:
        std::shared_ptr<gr::thread::thread> d_thread;
        std::vector<int> d_framenumbers;
        std::vector<int> d_timeslots;
        std::vector<std::string> d_burst_data;
        bool d_finished;
        uint16_t d_arfcn;
        void run();
     public:
        burst_source_impl(const std::vector<int> &framenumbers,
            const std::vector<int> &timeslots,
            const std::vector<std::string> &burst_data);
        ~burst_source_impl();
        virtual void set_framenumbers(const std::vector<int> &framenumbers);
        virtual void set_timeslots(const std::vector<int> &timeslots);
        virtual void set_burst_data(const std::vector<std::string> &burst_data);
        virtual void set_arfcn(uint16_t arfcn);
        bool start();
        bool stop();
        bool finished();
    };
  } // namespace gsm
} // namespace gr

#endif /* INCLUDED_GSM_BURST_SOURCE_IMPL_H */


