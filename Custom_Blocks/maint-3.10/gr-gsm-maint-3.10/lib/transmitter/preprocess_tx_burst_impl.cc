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

#include <assert.h>

#include <gnuradio/io_signature.h>
#include <gsm/gsm_constants.h>
#include <gsm/gsmtap.h>

#include "preprocess_tx_burst_impl.h"

namespace gr {
  namespace gsm {

    preprocess_tx_burst::sptr
    preprocess_tx_burst::make()
    {
      return gnuradio::get_initial_sptr
        (new preprocess_tx_burst_impl());
    }

    /*
     * The private constructor
     */
    preprocess_tx_burst_impl::preprocess_tx_burst_impl()
      : gr::block("preprocess_tx_burst",
        gr::io_signature::make(0, 0, 0),
        gr::io_signature::make(0, 0, 0))
    {
        message_port_register_in(pmt::mp("bursts_in"));
        message_port_register_out(pmt::mp("bursts_out"));

        set_msg_handler(pmt::mp("bursts_in"),
          boost::bind(&preprocess_tx_burst_impl::process_burst, this, boost::placeholders::_1));
    }

    /*
     * Our virtual destructor.
     */
    preprocess_tx_burst_impl::~preprocess_tx_burst_impl()
    {
    }
    
    void preprocess_tx_burst_impl::process_burst(pmt::pmt_t msg_in)
    {
      pmt::pmt_t blob_in = pmt::cdr(msg_in);

      // Extract GSMTAP header from message
      gsmtap_hdr *burst_hdr = (gsmtap_hdr *) pmt::blob_data(blob_in);

      // Extract burst bits from message
      uint8_t *burst_bits = (uint8_t *)
        (pmt::blob_data(blob_in)) + sizeof(gsmtap_hdr);

      // Determine and check burst length
      size_t burst_len = pmt::blob_length(blob_in) - sizeof(gsmtap_hdr);
      assert(burst_len == BURST_SIZE);

      // The Access Burst last has reduced length
      if (burst_hdr->sub_type == GSMTAP_BURST_ACCESS)
        burst_len = ACCESS_BURST_SIZE;

      // Prepare an output message
      pmt::pmt_t blob_out = pmt::make_blob(burst_bits, burst_len);
      pmt::pmt_t msg_out = pmt::cons(pmt::car(msg_in), blob_out);

      /* Send a message to the output */
      message_port_pub(pmt::mp("bursts_out"), msg_out);
    }

  } /* namespace gsm */
} /* namespace gr */
