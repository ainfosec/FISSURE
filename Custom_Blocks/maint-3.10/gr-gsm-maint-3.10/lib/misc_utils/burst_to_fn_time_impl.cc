/* -*- c++ -*- */
/* @file
 * @author Piotr Krysik <ptrkrysik@gmail.com>
 * @author Vadim Yanitskiy <axilirator@gmail.com>
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
#include "burst_to_fn_time_impl.h"

namespace gr {
  namespace gsm {

    burst_to_fn_time::sptr
    burst_to_fn_time::make(void)
    {
      return gnuradio::get_initial_sptr
        (new burst_to_fn_time_impl());
    }

    /*
     * The private constructor
     */
    burst_to_fn_time_impl::burst_to_fn_time_impl(void)
      : gr::block("burst_to_fn_time",
        gr::io_signature::make(0, 0, 0),
        gr::io_signature::make(0, 0, 0))
    {
        // Register I/O ports
        message_port_register_in(pmt::mp("bursts_in"));
        message_port_register_out(pmt::mp("fn_time_out"));

        // Bind a port handler
        set_msg_handler(pmt::mp("bursts_in"),
          boost::bind(&burst_to_fn_time_impl::handle_burst, this, boost::placeholders::_1));
    }

    /*
     * Our virtual destructor.
     */
    burst_to_fn_time_impl::~burst_to_fn_time_impl()
    {
    }

    void
    burst_to_fn_time_impl::handle_burst(pmt::pmt_t msg_in)
    {
      // Obtain fn_time tag from message
      pmt::pmt_t blob = pmt::car(msg_in);
      pmt::pmt_t fn_time = pmt::dict_ref(blob,
        pmt::intern("fn_time"), pmt::PMT_NIL);

      // Drop messages without required tag
      if (fn_time == pmt::PMT_NIL)
        return;

      // Compose and send a new message
      pmt::pmt_t msg_out = pmt::dict_add(pmt::make_dict(),
        pmt::intern("fn_time"), fn_time);
      message_port_pub(pmt::mp("fn_time_out"), msg_out);
    }

  } /* namespace gsm */
} /* namespace gr */
