/*
 * Copyright (C) 2013 Christoph Leitner <c.leitner@student.uibk.ac.at>
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

#include "ruc_connection.h"
#include "stubborn_sender.h"
#include "uc_connection.h"

#define DEBUG 1
#define dout DEBUG && std::cout


using namespace gr::ieee802_15_4;

ruc_connection::ruc_connection(rime_stack* block, uint16_t channel, 
							   pmt::pmt_t inport, pmt::pmt_t outport, 
							   const uint8_t rime_add_mine[2])
	: rime_connection(block, channel, inport, outport, rime_add_mine),
	d_stubborn_sender(block, this, d_mac_outport), d_send_seqno(0), d_recv_seqno(0)
{
	d_stubborn_sender.start();
}

std::array<uint8_t, 256>
ruc_connection::make_msgbuf(uint16_t channel, bool ack, int seqno,
		const uint8_t src[2], const uint8_t dest[2])
{
	std::array<uint8_t,256> buf;
	buf[0] = channel & 0xff;
	buf[1] = (channel >> 8) & 0xff;
	if(ack){
		buf[2]  = (1 << 7) & 0xff;	//ack packet
	} else {
		buf[2] = 0;	//data packet
	}

	buf[2] |= seqno << (7 - seqno_bits); //set seq.no.
	buf[2] |= dest[0] >> (1 + seqno_bits);
	buf[3]  = (dest[0] << (7 - seqno_bits)) & 0xff;
	buf[3] |= dest[1] >> (1 + seqno_bits);
	buf[4]  = (dest[1] << (7 - seqno_bits)) & 0xff;
	buf[4] |= src[0] >> (1 + seqno_bits);
	buf[5]  = (src[0] << (7 - seqno_bits)) & 0xff;
	buf[5] |= src[1] >> (1 + seqno_bits);
	buf[6]  = (src[1] << (7 - seqno_bits)) & 0xff;
	return buf;
}



void
ruc_connection::pack(pmt::pmt_t msg)
{
	assert(d_send_seqno < (1 << seqno_bits));

	if(pmt::is_eof_object(msg)){
		d_block->message_port_pub(d_mac_outport, pmt::PMT_EOF);
		d_block->detail().get()->set_done(true);
		return;
	}

	std::string tmp = rime_connection::msg_to_string(msg);

	uint8_t dest[2];
	if(!uc_connection::rime_add_from_string(tmp, dest)){
		std::cerr << "Warning: invalid target RIME-Address for runicast on channel ";
		std::cerr << static_cast<unsigned>(d_channel);
		std::cerr <<  ". Message will not be sent." << std::endl;
		return;
	}

	std::array<uint8_t, 256> buf = ruc_connection::make_msgbuf(d_channel, false,
			d_send_seqno, d_rime_add_mine, dest);

	size_t data_len = tmp.length();
	assert(data_len);
	assert(data_len < 256 - header_length);

	std::memcpy(buf.data() + header_length, tmp.data(), data_len);
	pmt::pmt_t rime_msg = pmt::make_blob(buf.data(), data_len + header_length);
	pmt::pmt_t dict = pmt::make_dict();
	dict = pmt::dict_add(dict, pmt::mp("seqno"), pmt::from_long(d_send_seqno));

	d_stubborn_sender.enqueue(pmt::cons(dict, rime_msg));
	d_send_seqno = (d_send_seqno + 1)%(1 << seqno_bits);
}

void
ruc_connection::unpack(pmt::pmt_t msg)
{
	uint8_t buf[256];
	uint8_t target_rime_zero, target_rime_one;
	uint8_t sender_rime_zero, sender_rime_one;
	bool is_ack = false;
	uint8_t packet_seqno;
	size_t data_len = pmt::blob_length(msg);
	std::memcpy(buf, pmt::blob_data(msg), data_len);

	target_rime_zero  = buf[2] << (1 + seqno_bits);
	target_rime_zero |= buf[3] >> (7 - seqno_bits);
	target_rime_one   = buf[3] << (1 + seqno_bits);
	target_rime_one  |= buf[4] >> (7 - seqno_bits);
	sender_rime_zero  = buf[4] << (1 + seqno_bits);
	sender_rime_zero |= buf[5] >> (7 - seqno_bits);
	sender_rime_one   = buf[5] << (1 + seqno_bits);
	sender_rime_one  |= buf[6] >> (7 - seqno_bits);

	dout << "[" << static_cast<int>(d_rime_add_mine[0]) << ".";
	dout << static_cast<int>(d_rime_add_mine[1]) << "]: ";

	//this block is not the destination of the message
	if(target_rime_zero != d_rime_add_mine[0] || target_rime_one != d_rime_add_mine[1]){
		dout << "received packet with wrong receiver, discarding";
		dout << "(" << static_cast<int>(target_rime_zero) << ".";
		dout << static_cast<int>(target_rime_one) << ")" << std::endl;
		return;
	}

	if((buf[2] & 0x80) > 0){
		is_ack = true;
		buf[2] &= 0x7f; //reset ack-flag
	}

	packet_seqno = buf[2] >> (7 - seqno_bits);

	if(is_ack){
		if(packet_seqno != recv_seqno()){ //ignore duplicate packets
		dout << "received duplicate ack ";
		dout << static_cast<int>(packet_seqno);
		dout << " (should be: ";
		dout << recv_seqno() << ")"<< std::endl;
		return;
	}
		dout << "received ack for seqno ";
		dout << static_cast<int>(packet_seqno) << std::endl;

		d_stubborn_sender.stop();
		inc_recv_seqno();

		dout << "expected next seqno: " << d_recv_seqno << std::endl;

	} else { 
		//output message
		pmt::pmt_t rime_payload = pmt::make_blob(buf + header_length,
													data_len - header_length);
		d_block->message_port_pub(d_outport, 
								  pmt::cons(pmt::PMT_NIL, rime_payload));

		//send ack
		uint8_t dest[] = {sender_rime_zero, sender_rime_one};
		std::array<uint8_t, 256> buf = make_msgbuf(d_channel, true,
				packet_seqno, d_rime_add_mine, dest);

		dout << "sent ack message for seqno " << static_cast<int>(packet_seqno);
		dout << " to ";
		dout << static_cast<int>(dest[0]) << ".";
		dout << static_cast<int>(dest[1]) << std::endl;

		pmt::pmt_t ack_msg = pmt::make_blob(buf.data(), header_length);
		d_block->message_port_pub(d_mac_outport,
								  pmt::cons(pmt::PMT_NIL, ack_msg));
	}
}

void
ruc_connection::inc_recv_seqno()
{
	gr::thread::scoped_lock lock(d_mutex);
	d_recv_seqno = (d_recv_seqno + 1)%(1 << seqno_bits);
}

int
ruc_connection::recv_seqno()
{
	gr::thread::scoped_lock lock(d_mutex);
	return d_recv_seqno;
}



