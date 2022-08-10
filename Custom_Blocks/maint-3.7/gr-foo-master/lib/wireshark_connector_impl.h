/*
 * Copyright (C) 2013 Bastian Bloessl <bloessl@ccs-labs.org>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#ifndef INCLUDED_FOO_WIRESHARK_CONNECTOR_IMPL_H
#define INCLUDED_FOO_WIRESHARK_CONNECTOR_IMPL_H

#include <foo/wireshark_connector.h>
#include <boost/cstdint.hpp>

namespace gr {
namespace foo {

	class wireshark_connector_impl : public wireshark_connector {
		private:
			uint8_t encoding_to_rate(uint64_t encoding);
			void handle_pdu(pmt::pmt_t pdu);

			bool        d_debug;
			int         d_msg_offset;
			int         d_msg_len;
			char*       d_msg;
			LinkType    d_link;
		public:
			wireshark_connector_impl(LinkType type, bool debug);
			int general_work(int noutput, gr_vector_int& ninput_items,
					gr_vector_const_void_star& input_items,
					gr_vector_void_star& output_items );
	};

	struct pcap_file_hdr {
		uint32_t magic_number;   /* magic number */
		uint16_t version_major;  /* major version number */
		uint16_t version_minor;  /* minor version number */
		int32_t  thiszone;       /* GMT to local correction */
		uint32_t sigfigs;        /* accuracy of timestamps */
		uint32_t snaplen;        /* max length of captured packets, in octets */
		uint32_t network;        /* data link type */
	}__attribute__((packed));

	struct pcap_hdr {
		uint32_t ts_sec;         /* timestamp seconds */
		uint32_t ts_usec;        /* timestamp microseconds */
		uint32_t incl_len;       /* number of octets of packet saved in file */
		uint32_t orig_len;       /* actual length of packet */
	}__attribute__((packed));

	struct radiotap_hdr {
		uint16_t version;
		uint16_t hdr_length;
		uint32_t bitmap;
		uint8_t  flags;
		uint8_t  rate;
		uint32_t channel;
		uint8_t  signal;
		uint8_t  noise;
		uint8_t  antenna;
	}__attribute__((packed));

}  // namespace foo
}  // namespace gr

#endif /* INCLUDED_FOO_WIRESHARK_CONNECTOR_IMPL_H */
