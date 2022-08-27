/*
 * Copyright (C) 2014, 2016 Bastian Bloessl <bloessl@ccs-labs.org>
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
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "encoder_impl.h"
#include "constants.h"
#include <gnuradio/io_signature.h>
#include <boost/spirit/include/qi.hpp>
#include <math.h>
#include <ctype.h>
#include <time.h>
#include <cstdio>

using namespace gr::rds;

encoder_impl::encoder_impl (unsigned char pty_locale, int pty, bool ms,
		std::string ps, double af1, bool tp,
		bool ta, int pi_country_code, int pi_coverage_area,
		int pi_reference_number, std::string radiotext)
	: gr::sync_block ("gr_rds_encoder",
			gr::io_signature::make (0, 0, 0),
			gr::io_signature::make (1, 1, sizeof(unsigned char))),
	pty_locale(pty_locale) {

	message_port_register_in(pmt::mp("rds in"));
	set_msg_handler(pmt::mp("rds in"), [this](pmt::pmt_t msg) { this->rds_in(msg); });

	std::memset(infoword,    0, sizeof(infoword));
	std::memset(checkword,   0, sizeof(checkword));
	std::memset(groups,      0, sizeof(groups));

	nbuffers             = 0;
	d_g0_counter         = 0;
	d_g2_counter         = 0;
	d_current_buffer     = 0;
	d_buffer_bit_counter = 0;

	PI                   = (pi_country_code & 0xF) << 12 |
	                       (pi_coverage_area & 0xF) << 8 |
	                       (pi_reference_number);
	PTY                  = pty;     // programm type (education)
	TP                   = tp;      // traffic programm
	TA                   = ta;      // traffic announcement
	MS                   = ms;      // music/speech switch (1=music)
	AF1                  = af1;     // alternate frequency 1

	DP                   = 3;
	extent               = 2;
	event                = 1340;
	location             = 11023;

	set_radiotext(std::string(radiotext));
	set_ps(ps);

	// which groups are set
	groups[ 0] = 1; // basic tuning and switching
	groups[ 1] = 1; // Extended Country Code
	groups[ 2] = 1; // radio text
	groups[ 3] = 1; // announce TMC
	groups[ 4] = 1; // clock time
	groups[ 8] = 1; // tmc
	groups[11] = 1;

	rebuild();
}

encoder_impl::~encoder_impl() {
	free(buffer);
}

void encoder_impl::rebuild() {
	gr::thread::scoped_lock lock(d_mutex);

	count_groups();
	d_current_buffer = 0;

	// allocate memory for nbuffers buffers of 104 unsigned chars each
	buffer = (unsigned char **)malloc(nbuffers * sizeof(unsigned char *));
	for(int i = 0; i < nbuffers; i++) {
		buffer[i] = (unsigned char *)malloc(104 * sizeof(unsigned char));
		for(int j = 0; j < 104; j++) buffer[i][j] = 0;
	}
	//printf("%i buffers allocated\n", nbuffers);

	// prepare each of the groups
	for(int i = 0; i < 32; i++) {
		if(groups[i] == 1) {
			create_group(i % 16, (i < 16) ? false : true);
			if(i % 16 == 0)  // if group is type 0, call 3 more times
				for(int j = 0; j < 3; j++) create_group(i % 16, (i < 16) ? false : true);
			if(i % 16 == 2) // if group type is 2, call 15 more times
				for(int j = 0; j < 15; j++) create_group(i % 16, (i < 16) ? false : true);
			if(i % 16 == 3)  // if group is type 3, call 1 more times
				create_group(i % 16, (i < 16) ? false : true);
		}
	}

	d_current_buffer = 0;
	std::cout << "nbuffers: " << nbuffers << std::endl;
}

void encoder_impl::rds_in(pmt::pmt_t msg) {
	if(!pmt::is_pair(msg)) {
		return;
	}

	using std::cout;
	using std::endl;
	using boost::spirit::qi::phrase_parse;
	using boost::spirit::qi::lexeme;
	using boost::spirit::qi::char_;
	using boost::spirit::qi::hex;
	using boost::spirit::qi::int_;
	using boost::spirit::qi::uint_;
	using boost::spirit::qi::bool_;
	using boost::spirit::qi::double_;
	using boost::spirit::qi::space;
	using boost::spirit::qi::blank;
	using boost::spirit::qi::lit;

	int msg_len = pmt::blob_length(pmt::cdr(msg));
	std::string in = std::string((char*)pmt::blob_data(pmt::cdr(msg)), msg_len);
	cout << "input string: " << in << "   length: " << in.size() << endl;

	unsigned int ui1;
	std::string s1;
	bool b1;
	double d1;

	// state
	if(phrase_parse(in.begin(), in.end(),
			"status", space)) {
		cout << "print state" << endl;
		//print_state();

	// pty
	} else if(phrase_parse(in.begin(), in.end(),
			"pty" >> (("0x" >> hex) | uint_), space, ui1)) {
		cout << "set pty: " << ui1 << endl;
		set_pty(ui1);

	// radio text
	} else if(phrase_parse(in.begin(), in.end(),
			"text" >> lexeme[+(char_ - '\n')] >> -lit("\n"),
			space, s1)) {
		cout << "text: " << s1 << endl;
		set_radiotext(s1);

	// ps
	} else if(phrase_parse(in.begin(), in.end(),
			"ps" >> lexeme[+(char_ - '\n')] >> -lit("\n"),
			space, s1)) {
		cout << "ps: " << s1 << endl;
		set_ps(s1);

	// ta
	} else if(phrase_parse(in.begin(), in.end(),
			"ta" >> bool_,
			space, b1)) {
		cout << "ta: " << b1 << endl;
		set_ta(b1);

	// tp
	} else if(phrase_parse(in.begin(), in.end(),
			"tp" >> bool_,
			space, b1)) {
		cout << "tp: " << b1 << endl;
		set_tp(b1);

	// MS
	} else if(phrase_parse(in.begin(), in.end(),
			"ms" >> bool_,
			space, b1)) {
		cout << "ms: " << b1 << endl;
		set_ms(b1);

	// PI
	} else if(phrase_parse(in.begin(), in.end(),
			"pi" >> lit("0x") >> hex, space, ui1)) {
		cout << "set pi: " << ui1 << endl;
		set_pi(ui1);

	// AF1
	} else if(phrase_parse(in.begin(), in.end(),
			"af1" >> double_, space, d1)) {
		cout << "set af1: " << d1 << endl;
		set_af1(d1);

	// no match / unkonwn command
	} else {
		cout << "not understood" << endl;
	}

	rebuild();
}

// music/speech
void encoder_impl::set_ms(bool ms) {
	MS = ms;
	std::cout << "setting Music/Speech code to " << ms << " (";
	if(ms) std::cout << "music)" << std::endl;
	else std::cout << "speech)" << std::endl;
}

// alternate frequency
void encoder_impl::set_af1(double af1) {
	AF1 = af1;
}

// traffic program indication
void encoder_impl::set_tp(bool tp) {
	TP = tp;
}

// traffic announcment
void encoder_impl::set_ta(bool ta) {
	TA = ta;
}

// program type
void encoder_impl::set_pty(unsigned int pty) {
	if(pty > 31) {
		std::cout << "warning: ignoring invalid pty: " << std::endl;
	} else {
		PTY = pty;
		std::cout << "setting pty to " << pty << " (" << pty_table[pty][pty_locale] << ")" << std::endl;
	}
}

// program identification
void encoder_impl::set_pi(unsigned int pi) {
	if(pi > 0xFFFF) {
		std::cout << "warning: ignoring invalid pi: " << std::endl;
	} else {
		PI = pi;
		std::cout << "setting pi to " << std::hex << pi << std::endl;
		if(pi & 0xF000)
			std::cout << "    country code " << pi_country_codes[((pi & 0xF000) >> 12) - 1][0] << std::endl;
		else
			std::cout << "    country code 0 (incorrect)" << std::endl;
		std::cout << "    coverage area " << coverage_area_codes[(pi & 0xF00) >> 8] << std::endl;
		std::cout << "    program reference number " << (pi & 0xFF) << std::dec << std::endl;
	}
}

// radiotext
void encoder_impl::set_radiotext(std::string text) {
		size_t len = std::min(sizeof(radiotext), text.length());

		std::memset(radiotext, ' ', sizeof(radiotext));
		std::memcpy(radiotext, text.c_str(), len);
}

// program service name
void encoder_impl::set_ps(std::string ps) {
		size_t len = std::min(sizeof(PS), ps.length());

		std::memset(PS, ' ', sizeof(PS));
		std::memcpy(PS, ps.c_str(), len);

		std::cout << "PS set to \"" << ps << "\"" << std::endl;
		rebuild();
}

/* see Annex B, page 64 of the standard */
unsigned int encoder_impl::calc_syndrome(unsigned long message,
		unsigned char mlen) {

	unsigned long reg = 0;
	unsigned int i;
	const unsigned long poly = 0x5B9;
	const unsigned char plen = 10;

	for (i = mlen; i > 0; i--)  {
		reg = (reg << 1) | ((message >> (i - 1)) & 0x01);
		if (reg & (1 << plen)) reg = reg ^ poly;
	}
	for (i = plen; i > 0; i--) {
		reg = reg << 1;
		if (reg & (1 << plen)) reg = reg ^ poly;
	}
	return reg & ((1 << plen) - 1);
}

/* see page 41 in the standard; this is an implementation of AF method A
 * FIXME need to add code that declares the number of AF to follow... */
unsigned int encoder_impl::encode_af(const double af) {
	std::cout << "encoding " << af << std::endl;
	unsigned int af_code = 0;
	if(( af >= 87.6) && (af <= 107.9))
		af_code = nearbyint((af - 87.5) * 10);
	else if((af >= 153) && (af <= 279))
		af_code = nearbyint((af - 144) / 9);
	else if((af >= 531) && (af <= 1602))
		af_code = nearbyint((af - 531) / 9 + 16);
	else
		printf("invalid alternate frequency: %f\n", af);
	return af_code;
}

/* count and print present groups */
void encoder_impl::count_groups(void) {
	int ngroups = 0;
	nbuffers = 0;
	//printf("groups present: ");
	for(int i = 0; i < 32; i++) {
		if(groups[i] == 1) {
			ngroups++;
			//printf("%i%c ", i % 16, (i < 16) ? 'A' : 'B');
			if(i % 16 == 0)  // group 0
				nbuffers += 4;
			else if(i % 16 == 2)  // group 2
				nbuffers += 16;
			else if(i % 16 == 3)
				nbuffers += 2;
			else
				nbuffers++;
		}
	}
	//printf("(%i groups)\n", ngroups);
}

/* create the 4 infowords, according to group type.
 * then calculate checkwords and put everything in the groups */
void encoder_impl::create_group(const int group_type, const bool AB) {

	infoword[0] = PI;
	infoword[1] = (((group_type & 0xf) << 12) | (AB << 11) | (TP << 10) | (PTY << 5));

	if(group_type == 0) prepare_group0(AB);
	else if(group_type == 1) prepare_group1a();
	else if(group_type == 2) prepare_group2(AB);
	else if(group_type == 3) prepare_group3a();
	else if(group_type == 4) prepare_group4a();
	else if(group_type == 8) prepare_group8a();
	else if(group_type == 11) prepare_group11a();
	else printf("preparation of group %i not yet supported\n", group_type);
	//printf("data: %04X %04X %04X %04X, ", infoword[0], infoword[1], infoword[2], infoword[3]);

	for(int i= 0; i < 4; i++) {
		checkword[i]=calc_syndrome(infoword[i], 16);
		block[i] = ((infoword[i] & 0xffff) << 10) | (checkword[i] & 0x3ff);
		// add the offset word
		if((i == 2) && AB) block[2] ^= offset_word[4];
		else block[i] ^= offset_word[i];
	}
	//printf("group: %04X %04X %04X %04X\n", block[0], block[1], block[2], block[3]);

	prepare_buffer(d_current_buffer);
	d_current_buffer++;
}

void encoder_impl::prepare_group0(const bool AB) {
	std::cout << "preparing 0" << std::endl;
	infoword[1] = infoword[1] | (TA << 4) | (MS << 3);
	//FIXME: make DI configurable
	if(d_g0_counter == 3)
		infoword[1] = infoword[1] | 0x5;  // d0=1 (stereo), d1-3=0
	infoword[1] = infoword[1] | (d_g0_counter & 0x3);
	if(!AB) {
		infoword[2] = (225 << 8) | // 1 AF follows
			(encode_af(AF1/1000000) & 0xff);
	} else {
		infoword[2] = PI;
	}
	infoword[3] = (PS[2 * d_g0_counter] << 8) | PS[2 * d_g0_counter + 1];
	d_g0_counter++;
	if(d_g0_counter > 3) d_g0_counter = 0;
}

void encoder_impl::prepare_group2(const bool AB) {
	infoword[1] = infoword[1] | ((AB << 4) | (d_g2_counter & 0xf));
	if(!AB) {
		infoword[2] = (radiotext[d_g2_counter * 4] << 8 | radiotext[d_g2_counter * 4 + 1]);
		infoword[3] = (radiotext[d_g2_counter * 4 + 2] << 8 | radiotext[d_g2_counter * 4 + 3]);
	}
	else {
		infoword[2] = PI;
		infoword[3] = (radiotext[d_g2_counter * 2] << 8 | radiotext[d_g2_counter * 2 + 1]);
	}
	d_g2_counter++;
	d_g2_counter %= 16;
}

void encoder_impl::prepare_group1a(void) {
	std::cout << "preparing group 1" << std::endl;
	//infoword[1] = infoword[1] | (1 << 4); // TMC in 8A
	infoword[2] = (0x80 << 8) | 0xE0;
	infoword[3] = 0; // time
}

void encoder_impl::prepare_group3a(void) {
	std::cout << "preparing group 3" << std::endl;
	static int count = 0;
	if(count) {
		infoword[1] = infoword[1] | (0x31d0 & 0x1f);
		infoword[2] = 0x6280;
		infoword[3] = 0xcd46;
	} else {
		infoword[1] = infoword[1] | (0x31d0 & 0x1f);
		infoword[2] = 0x0066;
		infoword[3] = 0xcd46; // AID for TMC (Alert C)
	}
	count++;
	count = count % 2;
}

/* see page 28 and Annex G, page 81 in the standard */
/* FIXME this is supposed to be transmitted only once per minute, when
 * the minute changes */
void encoder_impl::prepare_group4a(void) {
	time_t rightnow;
	tm *utc;

	time(&rightnow);
	//printf("%s", asctime(localtime(&rightnow)));

	/* we're supposed to send UTC time; the receiver should then add the
	* local timezone offset */
	utc = gmtime(&rightnow);
	int m = utc->tm_min;
	int h = utc->tm_hour;
	int D = utc->tm_mday;
	int M = utc->tm_mon + 1;  // January: M=0
	int Y = utc->tm_year;
	int toffset=localtime(&rightnow)->tm_hour-h;

	int L = ((M == 1) || (M == 2)) ? 1 : 0;
	int mjd=14956+D+int((Y-L)*365.25)+int((M+1+L*12)*30.6001);

	infoword[1]=infoword[1]|((mjd>>15)&0x3);
	infoword[2]=(((mjd>>7)&0xff)<<8)|((mjd&0x7f)<<1)|((h>>4)&0x1);
	infoword[3]=((h&0xf)<<12)|(((m>>2)&0xf)<<8)|((m&0x3)<<6)|
		((toffset>0?0:1)<<5)|((abs(toffset*2))&0x1f);
}

// TMC Alert-C
void encoder_impl::prepare_group8a(void) {
	infoword[1] = infoword[1] | (1 << 3) | (DP & 0x7);
	infoword[2] = (1 << 15) | ((extent & 0x7) << 11) | (event & 0x7ff);
	infoword[3] = location;
}

// for now single-group only
void encoder_impl::prepare_group11a(void) {
	std::cout << "preparing group 11" << std::endl;
	infoword[1] = infoword[1] | (0xb1c8 & 0x1f);
	infoword[2] = 0x2038;
	infoword[3] = 0x4456;
}

void encoder_impl::prepare_buffer(int which) {
	int q=0, i=0, j=0, a=0, b=0;
	unsigned char temp[13]; // 13*8=104
	std::memset(temp, 0, 13);

	for(q = 0; q < 104; q++) {
		a = floor(q / 26);
		b = 25 - q % 26;
		buffer[which][q] = (unsigned char)(block[a] >> b) & 0x1;
		i = floor(q / 8);
		j = 7 - q % 8;
		temp[i] = temp[i]|(buffer[which][q] << j);
	}
	//printf("buffer[%i]: ", which);
	//for(i = 0; i < 13; i++) printf("%02X", temp[i]);
	//printf("\n");
}

//////////////////////// WORK ////////////////////////////////////
int encoder_impl::work (int noutput_items,
		gr_vector_const_void_star &input_items,
		gr_vector_void_star &output_items) {

	gr::thread::scoped_lock lock(d_mutex);
	unsigned char *out = (unsigned char *) output_items[0];

	for(int i = 0; i < noutput_items; i++) {
		out[i] = buffer[d_current_buffer][d_buffer_bit_counter];
		if(++d_buffer_bit_counter > 103) {
			d_buffer_bit_counter = 0;
			d_current_buffer++;
			d_current_buffer = d_current_buffer % nbuffers;
		}
	}

	return noutput_items;
}

encoder::sptr encoder::make (unsigned char pty_locale, int pty, bool ms,
		std::string ps, double af1, bool tp,
		bool ta, int pi_country_code, int pi_coverage_area,
		int pi_reference_number, std::string radiotext) {

	return gnuradio::get_initial_sptr(
			new encoder_impl(pty_locale, pty, ms, ps, af1, tp, ta,
					pi_country_code, pi_coverage_area, pi_reference_number,
					radiotext));
}
