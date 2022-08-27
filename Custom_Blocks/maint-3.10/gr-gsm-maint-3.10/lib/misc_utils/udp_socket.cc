/* -*- c++ -*- */
/*
 * Copyright 2013 Free Software Foundation, Inc.
 *
 * This file is part of GNU Radio
 *
 * GNU Radio is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3, or (at your option)
 * any later version.
 *
 * GNU Radio is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GNU Radio; see the file COPYING.  If not, write to
 * the Free Software Foundation, Inc., 51 Franklin Street,
 * Boston, MA 02110-1301, USA.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <gnuradio/thread/thread.h>
#include <gnuradio/io_signature.h>
#include <pmt/pmt.h>

#include <boost/lexical_cast.hpp>
#include "gsm/misc_utils/udp_socket.h"

using boost::asio::ip::udp;

namespace gr {
  namespace gsm {

    udp_socket::udp_socket(
      const std::string &bind_addr,
      const std::string &src_port,
      const std::string &remote_addr,
      const std::string &dst_port,
      size_t mtu)
    {
      // Resize receive buffer according to MTU value
      d_rxbuf.resize(mtu);

      // Resolve remote host address
      udp::resolver resolver(d_io_service);

      udp::resolver::query rx_query(
        udp::v4(), bind_addr, src_port,
        boost::asio::ip::resolver_query_base::passive);
      udp::resolver::query tx_query(
        udp::v4(), remote_addr, dst_port,
        boost::asio::ip::resolver_query_base::passive);

      d_udp_endpoint_rx = *resolver.resolve(rx_query);
      d_udp_endpoint_tx = *resolver.resolve(tx_query);

      // Create a socket
      d_udp_socket.reset(new udp::socket(d_io_service, d_udp_endpoint_rx));

      // Setup read handler
      d_udp_socket->async_receive_from(
        boost::asio::buffer(d_rxbuf), d_udp_endpoint_rx,
        boost::bind(&udp_socket::handle_udp_read, this,
          boost::asio::placeholders::error,
          boost::asio::placeholders::bytes_transferred));

      // Start server
      d_thread = gr::thread::thread(
        boost::bind(&udp_socket::run_io_service, this));
    }

    udp_socket::~udp_socket()
    {
      // Stop server
      d_io_service.stop();
      d_thread.interrupt();
      d_thread.join();
    }

    void
    udp_socket::run_io_service(void)
    {
      d_io_service.run();
    }

    void
    udp_socket::udp_send(uint8_t *data, size_t len)
    {
      d_udp_socket->send_to(
        boost::asio::buffer(data, len),
        d_udp_endpoint_tx);
    }

    void
    udp_socket::handle_udp_read(
      const boost::system::error_code& error,
      size_t bytes_transferred)
    {
      if (error)
        return;

      // Call incoming data handler
      if (udp_rx_handler != NULL)
        udp_rx_handler((uint8_t *) &d_rxbuf[0], bytes_transferred);

      d_udp_socket->async_receive_from(
        boost::asio::buffer(d_rxbuf), d_udp_endpoint_rx,
        boost::bind(&udp_socket::handle_udp_read, this,
          boost::asio::placeholders::error,
          boost::asio::placeholders::bytes_transferred));
    }

  } /* namespace gsm */
}/* namespace gr */
