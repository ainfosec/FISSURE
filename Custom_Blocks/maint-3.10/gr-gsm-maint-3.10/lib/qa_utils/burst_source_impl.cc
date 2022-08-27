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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <gnuradio/io_signature.h>
#include "burst_source_impl.h"
#include "stdio.h"
#include <boost/scoped_ptr.hpp>
#include <gsm/gsmtap.h>
#include <gsm/endian.h>

namespace gr {
  namespace gsm {

    burst_source::sptr
    burst_source::make(const std::vector<int> &framenumbers,
            const std::vector<int> &timeslots,
            const std::vector<std::string> &burst_data)
    {
      return gnuradio::get_initial_sptr
        (new burst_source_impl(framenumbers, timeslots, burst_data));
    }

    /*
     * The private constructor
     */
    burst_source_impl::burst_source_impl(const std::vector<int> &framenumbers,
            const std::vector<int> &timeslots,
            const std::vector<std::string> &burst_data)
      : gr::block("burst_source",
              gr::io_signature::make(0, 0, 0),
              gr::io_signature::make(0, 0, 0)),
              d_finished(false),
              d_arfcn(0)
    {
        message_port_register_out(pmt::mp("out"));
        set_framenumbers(framenumbers);
        set_timeslots(timeslots);
        set_burst_data(burst_data);
    }

    /*
     * Our virtual destructor.
     */
    burst_source_impl::~burst_source_impl()
    {
        if (d_finished == false){
            d_finished = true;
        }
    }

    void burst_source_impl::set_framenumbers(const std::vector<int> &framenumbers)
    {
        d_framenumbers = framenumbers;
    }

    void  burst_source_impl::set_timeslots(const std::vector<int> &timeslots)
    {
        d_timeslots = timeslots;
    }

    void burst_source_impl::set_burst_data(const std::vector<std::string> &burst_data)
    {
        d_burst_data = burst_data;
    }

    void burst_source_impl::set_arfcn(uint16_t arfcn)
    {
        d_arfcn = arfcn;
    }

    bool burst_source_impl::start()
    {
        d_finished = false;
        d_thread = std::shared_ptr<gr::thread::thread>
            (new gr::thread::thread(boost::bind(&burst_source_impl::run, this)));
        return block::start();
    }

    bool burst_source_impl::stop()
    {
        d_finished = true;
        d_thread->interrupt();
        d_thread->join();
        return block::stop();
    }

    bool burst_source_impl::finished()
    {
        return d_finished;
    }

    void burst_source_impl::run()
    {
        for (int i=0; i<d_burst_data.size(); i++)
        {
            if (d_burst_data[i].length() == BURST_SIZE &&
                d_timeslots[i] >= 0 && d_timeslots[i] <= 7 &&
                d_framenumbers[i] >= 0 && d_framenumbers[i] <= (26 * 51 * 2048 - 1))
            {
                boost::scoped_ptr<gsmtap_hdr> tap_header(new gsmtap_hdr());

                tap_header->version = GSMTAP_VERSION;
                tap_header->hdr_len = sizeof(gsmtap_hdr)/4;
                tap_header->type = GSMTAP_TYPE_UM_BURST;
                tap_header->timeslot = d_timeslots[i];
                tap_header->frame_number = htobe32(d_framenumbers[i]);
                tap_header->sub_type = GSMTAP_BURST_NORMAL;
                tap_header->arfcn = d_arfcn;
                tap_header->signal_dbm = 0;
                tap_header->snr_db = 0;

                uint8_t burst[BURST_SIZE];

                for (int j=0; j<BURST_SIZE; j++)
                {
                    if (d_burst_data[i][j] == '0')
                    {
                        burst[j] = 0;
                    }
                    else
                    {
                        burst[j] = 1;
                    }
                }

                int8_t header_plus_burst[sizeof(gsmtap_hdr) + BURST_SIZE];
                memcpy(header_plus_burst, tap_header.get(), sizeof(gsmtap_hdr));
                memcpy(header_plus_burst + sizeof(gsmtap_hdr), burst, BURST_SIZE);

                pmt::pmt_t blob_header_plus_burst = pmt::make_blob(header_plus_burst, sizeof(gsmtap_hdr) + BURST_SIZE);
                pmt::pmt_t msg = pmt::cons(pmt::PMT_NIL, blob_header_plus_burst);

                message_port_pub(pmt::mp("out"), msg);
            }
        }
        post(pmt::mp("system"), pmt::cons(pmt::mp("done"), pmt::from_long(1)));
    }
  } /* namespace gsm */
} /* namespace gr */


