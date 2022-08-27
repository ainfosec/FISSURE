/* -*- c++ -*- */
/* @file
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
#include <boost/lexical_cast.hpp>

#include "gsm/endian.h"
#include "gsm/misc_utils/udp_socket.h"
#include "trx_burst_if_impl.h"

#define BURST_SIZE     148
#define DATA_IF_MTU    160

/**
 * 41-bit RACH synchronization sequence
 * GSM 05.02 Chapter 5.2.7 Access burst (AB)
 */
static uint8_t rach_synch_seq[] = {
  0, 1, 0, 0, 1, 0, 1, 1, 0, 1, 1, 1, 1, 1,
  1, 1, 1, 0, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0,
  1, 0, 1, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0,
};

namespace gr {
  namespace gsm {

    trx_burst_if::sptr
    trx_burst_if::make(
      const std::string &bind_addr,
      const std::string &remote_addr,
      const std::string &base_port)
    {
      int base_port_int = boost::lexical_cast<int> (base_port);

      return gnuradio::get_initial_sptr
        (new trx_burst_if_impl(bind_addr, remote_addr,
          base_port_int));
    }

    /*
     * The private constructor
     */
    trx_burst_if_impl::trx_burst_if_impl(
      const std::string &bind_addr,
      const std::string &remote_addr,
      int base_port
    ) : gr::block("trx_burst_if",
        gr::io_signature::make(0, 0, 0),
        gr::io_signature::make(0, 0, 0))
    {
        message_port_register_in(pmt::mp("bursts"));
        message_port_register_out(pmt::mp("bursts"));

        // Bind a port handler
        set_msg_handler(pmt::mp("bursts"),
          boost::bind(&trx_burst_if_impl::handle_dl_burst, this, boost::placeholders::_1));

        // Prepare port numbers
        std::string data_src_port = boost::lexical_cast<std::string> (base_port + 2);
        std::string data_dst_port = boost::lexical_cast<std::string> (base_port + 102);

        // Init DATA interface
        d_data_sock = new udp_socket(bind_addr, data_src_port,
          remote_addr, data_dst_port, DATA_IF_MTU);

        // Bind DATA interface handler
        d_data_sock->udp_rx_handler = boost::bind(
          &trx_burst_if_impl::handle_ul_burst, this, boost::placeholders::_1, boost::placeholders::_2);
    }

    /*
     * Our virtual destructor.
     */
    trx_burst_if_impl::~trx_burst_if_impl()
    {
        // Release all UDP sockets and free memory
        delete d_data_sock;
    }

    /*
     * Check if burst is a RACH burst
     */
    bool trx_burst_if_impl::detect_rach(uint8_t *burst)
    {
      // Compare synchronization sequence
      for (int i = 0; i < 41; i++)
        if (burst[i + 8] != rach_synch_seq[i])
          return false;

      // Make sure TB and GP are filled by 0x00
      for (int i = 0; i < 63; i++)
        if (burst[i + 85] != 0x00)
          return false;

      return true;
    }

    /*
     * Create an UDP payload with burst bits
     * and some channel data.
     */
    void
    trx_burst_if_impl::burst_pack(pmt::pmt_t msg, uint8_t *buf)
    {
      pmt::pmt_t header_plus_burst = pmt::cdr(msg);

      // Extract GSMTAP header from message
      gsmtap_hdr *header = (gsmtap_hdr *)
        pmt::blob_data(header_plus_burst);

      // Pack timeslot index
      buf[0] = header->timeslot;

      // Extract frame number
      uint32_t frame_nr = be32toh(header->frame_number);

      // Pack frame number
      buf[1] = (frame_nr >> 24) & 0xff;
      buf[2] = (frame_nr >> 16) & 0xff;
      buf[3] = (frame_nr >>  8) & 0xff;
      buf[4] = (frame_nr >>  0) & 0xff;

      // Pack RSSI (-dBm)
      buf[5] = -(uint8_t) header->signal_dbm;

      // Pack correlator timing offset (TOA)
      // FIXME: where to find this value?
      buf[6] = 0;
      buf[7] = 0;

      // Extract bits {0..1} from message
      // Despite GR-GSM uses int8_t, they are not real sbits {-127..127}
      uint8_t *burst = (uint8_t *)
        (pmt::blob_data(header_plus_burst)) + sizeof(gsmtap_hdr);

      // Convert to transceiver interface specific bits {255..0}
      for (int i = 0; i < 148; i++)
        buf[8 + i] = burst[i] ? 255 : 0;

      // Fill two unused bytes
      buf[156] = 0x00;
      buf[157] = 0x00;
    }

    void
    trx_burst_if_impl::handle_dl_burst(pmt::pmt_t msg)
    {
      // 8 bytes of header + 148 bytes of burst
      // + two unused, but required bytes
      // otherwise bursts would be rejected
      uint8_t buf[158];

      // Compose a new UDP payload with burst
      burst_pack(msg, buf);

      // Send a burst
      d_data_sock->udp_send(buf, 158);
    }

    void
    trx_burst_if_impl::handle_ul_burst(uint8_t *payload, size_t len)
    {
      // Check length according to the protocol
      if (len != 154)
        return;

      /* Make sure TS index is correct */
      if (payload[0] >= 8)
        return;

      /* Unpack and check frame number */
      uint32_t fn = (payload[1] << 24)
        | (payload[2] << 16)
        | (payload[3] << 8)
        | payload[4];

      if (fn >= 2715648)
        return;

      // Prepare a buffer for GSMTAP header and burst
      uint8_t buf[sizeof(gsmtap_hdr) + BURST_SIZE];

      // Set up pointer to GSMTAP header structure
      struct gsmtap_hdr *header = (struct gsmtap_hdr *) buf;
      memset(header, 0x00, sizeof(struct gsmtap_hdr));

      // Fill in basic info
      header->version = GSMTAP_VERSION;
      header->hdr_len = sizeof(gsmtap_hdr) / 4;
      header->type = GSMTAP_TYPE_UM_BURST;

      // Set timeslot index and frame number
      header->timeslot = payload[0];
      header->frame_number = htobe32(fn);

      // Check if one is a RACH burst
      header->sub_type = detect_rach(payload + 6) ?
        GSMTAP_BURST_ACCESS : GSMTAP_BURST_NORMAL;

      // Copy burst bits (0 & 1) for source message
      memcpy(buf + sizeof(gsmtap_hdr), payload + 6, BURST_SIZE);

      // Create a pmt blob
      pmt::pmt_t blob = pmt::make_blob(buf, sizeof(gsmtap_hdr) + BURST_SIZE);
      pmt::pmt_t msg = pmt::cons(pmt::PMT_NIL, blob);

      /* Send a message to the output */
      message_port_pub(pmt::mp("bursts"), msg);
    }

  } /* namespace gsm */
} /* namespace gr */
