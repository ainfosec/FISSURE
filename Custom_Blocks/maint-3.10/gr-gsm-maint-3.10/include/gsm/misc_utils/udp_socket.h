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

#ifndef INCLUDED_GSM_TRX_UDP_SOCKET_H
#define INCLUDED_GSM_TRX_UDP_SOCKET_H

#include <gnuradio/thread/thread.h>

#include <boost/function.hpp>
#include <boost/array.hpp>
#include <boost/asio.hpp>
#include <pmt/pmt.h>

namespace gr {
  namespace gsm {

    class udp_socket
    {
    private:
      boost::asio::io_service d_io_service;
      std::vector<char> d_rxbuf;
      gr::thread::thread d_thread;
      bool d_started;
      bool d_finished;

      boost::asio::ip::udp::endpoint d_udp_endpoint_rx;
      boost::asio::ip::udp::endpoint d_udp_endpoint_tx;
      std::shared_ptr<boost::asio::ip::udp::socket> d_udp_socket;

      void handle_udp_read(const boost::system::error_code& error,
        size_t bytes_transferred);
      void run_io_service(void);

    public:
      udp_socket(
        const std::string &bind_addr,
        const std::string &src_port,
        const std::string &remote_addr,
        const std::string &dst_port,
        size_t mtu);
      ~udp_socket();

      void udp_send(uint8_t *data, size_t len);
      boost::function<void (uint8_t *, size_t)> udp_rx_handler;
    };

  } /* namespace gsm */
} /* namespace gr */

#endif /* INCLUDED_GSM_TRX_UDP_SOCKET_H */
