/*! \file conv.c
 * Generic convolutional encoding / decoding. */
/*
 * Copyright (C) 2011  Sylvain Munaut <tnt@246tNt.com>
 *
 * All Rights Reserved
 *
 * SPDX-License-Identifier: GPL-2.0+
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/*! \addtogroup conv
 *  @{
 *  Osmocom convolutional encoder and decoder.
 *
 * \file conv.c */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef HAVE_ALLOCA_H
#include <alloca.h>
#endif
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <osmocom/core/bits.h>
#include <osmocom/core/conv.h>


/* ------------------------------------------------------------------------ */
/* Common                                                                   */
/* ------------------------------------------------------------------------ */

int
osmo_conv_get_input_length(const struct osmo_conv_code *code, int len)
{
	return len <= 0 ? code->len : len;
}

int
osmo_conv_get_output_length(const struct osmo_conv_code *code, int len)
{
	int pbits, in_len, out_len;

	/* Input length */
	in_len = osmo_conv_get_input_length(code, len);

	/* Output length */
	out_len = in_len * code->N;

	if (code->term == CONV_TERM_FLUSH)
		out_len += code->N * (code->K - 1);

	/* Count punctured bits */
	if (code->puncture) {
		for (pbits=0; code->puncture[pbits] >= 0; pbits++);
		out_len -= pbits;
	}

	return out_len;
}


/* ------------------------------------------------------------------------ */
/* Encoding                                                                 */
/* ------------------------------------------------------------------------ */

/*! Initialize a convolutional encoder
 *  \param[in,out] encoder Encoder state to initialize
 *  \param[in] code Description of convolutional code
 */
void
osmo_conv_encode_init(struct osmo_conv_encoder *encoder,
                      const struct osmo_conv_code *code)
{
	memset(encoder, 0x00, sizeof(struct osmo_conv_encoder));
	encoder->code = code;
}

void
osmo_conv_encode_load_state(struct osmo_conv_encoder *encoder,
                            const ubit_t *input)
{
	int i;
	uint8_t state = 0;

	for (i=0; i<(encoder->code->K-1); i++)
		state = (state << 1) | input[i];

	encoder->state = state;
}

static inline int
_conv_encode_do_output(struct osmo_conv_encoder *encoder,
                       uint8_t out, ubit_t *output)
{
	const struct osmo_conv_code *code = encoder->code;
	int o_idx = 0;
	int j;

	if (code->puncture) {
		for (j=0; j<code->N; j++)
		{
			int bit_no = code->N - j - 1;
			int r_idx = encoder->i_idx * code->N + j;

			if (code->puncture[encoder->p_idx] == r_idx)
				encoder->p_idx++;
			else
				output[o_idx++] = (out >> bit_no) & 1;
		}
	} else {
		for (j=0; j<code->N; j++)
		{
			int bit_no = code->N - j - 1;
			output[o_idx++] = (out >> bit_no) & 1;
		}
	}

	return o_idx;
}

int
osmo_conv_encode_raw(struct osmo_conv_encoder *encoder,
                     const ubit_t *input, ubit_t *output, int n)
{
	const struct osmo_conv_code *code = encoder->code;
	uint8_t state;
	int i;
	int o_idx;

	o_idx = 0;
	state = encoder->state;

	for (i=0; i<n; i++) {
		int bit = input[i];
		uint8_t out;

		out   = code->next_output[state][bit];
		state = code->next_state[state][bit];

		o_idx += _conv_encode_do_output(encoder, out, &output[o_idx]);

		encoder->i_idx++;
	}

	encoder->state = state;

	return o_idx;
}

int
osmo_conv_encode_flush(struct osmo_conv_encoder *encoder,
                       ubit_t *output)
{
	const struct osmo_conv_code *code = encoder->code;
	uint8_t state;
	int n;
	int i;
	int o_idx;

	n = code->K - 1;

	o_idx = 0;
	state = encoder->state;

	for (i=0; i<n; i++) {
		uint8_t out;

		if (code->next_term_output) {
			out   = code->next_term_output[state];
			state = code->next_term_state[state];
		} else {
			out   = code->next_output[state][0];
			state = code->next_state[state][0];
		}

		o_idx += _conv_encode_do_output(encoder, out, &output[o_idx]);

		encoder->i_idx++;
	}

	encoder->state = state;

	return o_idx;
}

/*! All-in-one convolutional encoding function
 *  \param[in] code description of convolutional code to be used
 *  \param[in] input array of unpacked bits (uncoded)
 *  \param[out] output array of unpacked bits (encoded)
 *  \return Number of produced output bits
 *
 * This is an all-in-one function, taking care of
 * \ref osmo_conv_init, \ref osmo_conv_encode_load_state,
 * \ref osmo_conv_encode_raw and \ref osmo_conv_encode_flush as needed.
 */
int
osmo_conv_encode(const struct osmo_conv_code *code,
                 const ubit_t *input, ubit_t *output)
{
	struct osmo_conv_encoder encoder;
	int l;

	osmo_conv_encode_init(&encoder, code);

	if (code->term == CONV_TERM_TAIL_BITING) {
		int eidx = code->len - code->K + 1;
		osmo_conv_encode_load_state(&encoder, &input[eidx]);
	}

	l = osmo_conv_encode_raw(&encoder, input, output, code->len);

	if (code->term == CONV_TERM_FLUSH)
		l += osmo_conv_encode_flush(&encoder, &output[l]);

	return l;
}


/* ------------------------------------------------------------------------ */
/* Decoding (viterbi)                                                       */
/* ------------------------------------------------------------------------ */

#define MAX_AE 0x00ffffff

/* Forward declaration for accerlated decoding with certain codes */
int
osmo_conv_decode_acc(const struct osmo_conv_code *code,
                     const sbit_t *input, ubit_t *output);

void
osmo_conv_decode_init(struct osmo_conv_decoder *decoder,
                      const struct osmo_conv_code *code, int len, int start_state)
{
	int n_states;

	/* Init */
	if (len <= 0)
		len =  code->len;

	n_states = 1 << (code->K - 1);

	memset(decoder, 0x00, sizeof(struct osmo_conv_decoder));

	decoder->code = code;
	decoder->n_states = n_states;
	decoder->len = len;

	/* Allocate arrays */
	decoder->ae      = malloc(sizeof(unsigned int) * n_states);
	decoder->ae_next = malloc(sizeof(unsigned int) * n_states);

	decoder->state_history = malloc(sizeof(uint8_t) * n_states * (len + decoder->code->K - 1));

	/* Classic reset */
	osmo_conv_decode_reset(decoder, start_state);
}

void
osmo_conv_decode_reset(struct osmo_conv_decoder *decoder, int start_state)
{
	int i;

	/* Reset indexes */
	decoder->o_idx = 0;
	decoder->p_idx = 0;

	/* Initial error */
	if (start_state < 0) {
		/* All states possible */
		memset(decoder->ae, 0x00, sizeof(unsigned int) * decoder->n_states);
	} else {
		/* Fixed start state */
		for (i=0; i<decoder->n_states; i++) {
			decoder->ae[i] = (i == start_state) ? 0 : MAX_AE;
		}
	}
}

void
osmo_conv_decode_rewind(struct osmo_conv_decoder *decoder)
{
	int i;
	unsigned int min_ae = MAX_AE;

	/* Reset indexes */
	decoder->o_idx = 0;
	decoder->p_idx = 0;

	/* Initial error normalize (remove constant) */
	for (i=0; i<decoder->n_states; i++) {
		if (decoder->ae[i] < min_ae)
			min_ae = decoder->ae[i];
	}

	for (i=0; i<decoder->n_states; i++)
		decoder->ae[i] -= min_ae;
}

void
osmo_conv_decode_deinit(struct osmo_conv_decoder *decoder)
{
	free(decoder->ae);
	free(decoder->ae_next);
	free(decoder->state_history);

	memset(decoder, 0x00, sizeof(struct osmo_conv_decoder));
}

int
osmo_conv_decode_scan(struct osmo_conv_decoder *decoder,
                      const sbit_t *input, int n)
{
	const struct osmo_conv_code *code = decoder->code;

	int i, s, b, j;

	int n_states;
	unsigned int *ae;
	unsigned int *ae_next;
	uint8_t *state_history;
	sbit_t *in_sym;

	int i_idx, p_idx;

	/* Prepare */
	n_states = decoder->n_states;

	ae      = decoder->ae;
	ae_next = decoder->ae_next;
	state_history = &decoder->state_history[n_states * decoder->o_idx];

	in_sym  = malloc(sizeof(sbit_t) * code->N);

	i_idx = 0;
	p_idx = decoder->p_idx;

	/* Scan the treillis */
	for (i=0; i<n; i++)
	{
		/* Reset next accumulated error */
		for (s=0; s<n_states; s++) {
			ae_next[s] = MAX_AE;
		}

		/* Get input */
		if (code->puncture) {
			/* Hard way ... */
			for (j=0; j<code->N; j++) {
				int idx = ((decoder->o_idx + i) * code->N) + j;
				if (idx == code->puncture[p_idx]) {
					in_sym[j] = 0;	/* Undefined */
					p_idx++;
				} else {
					in_sym[j] = input[i_idx];
					i_idx++;
				}
			}
		} else {
			/* Easy, just copy N bits */
			memcpy(in_sym, &input[i_idx], code->N);
			i_idx += code->N;
		}

		/* Scan all state */
		for (s=0; s<n_states; s++)
		{
			/* Scan possible input bits */
			for (b=0; b<2; b++)
			{
				int nae, ov, e;
				uint8_t m;

				/* Next output and state */
				uint8_t out   = code->next_output[s][b];
				uint8_t state = code->next_state[s][b];

				/* New error for this path */
				nae = ae[s];			/* start from last error */
				m = 1 << (code->N - 1);		/* mask for 'out' bit selection */

				for (j=0; j<code->N; j++) {
					int is = (int)in_sym[j];
					if (is) {
						ov = (out & m) ? -127 : 127; /* sbit_t value for it */
						e = is - ov;                 /* raw error for this bit */
						nae += (e * e) >> 9;         /* acc the squared/scaled value */
					}
					m >>= 1;                     /* next mask bit */
				}

				/* Is it survivor ? */
				if (ae_next[state] > nae) {
					ae_next[state] = nae;
					state_history[(n_states * i) + state] = s;
				}
			}
		}

		/* Copy accumulated error */
		memcpy(ae, ae_next, sizeof(unsigned int) * n_states);
	}

	/* Update decoder state */
	decoder->p_idx = p_idx;
	decoder->o_idx += n;

	free(in_sym);
	return i_idx;
}

int
osmo_conv_decode_flush(struct osmo_conv_decoder *decoder,
                       const sbit_t *input)
{
	const struct osmo_conv_code *code = decoder->code;

	int i, s, j;

	int n_states;
	unsigned int *ae;
	unsigned int *ae_next;
	uint8_t *state_history;
	sbit_t *in_sym;

	int i_idx, p_idx;

	/* Prepare */
	n_states = decoder->n_states;

	ae      = decoder->ae;
	ae_next = decoder->ae_next;
	state_history = &decoder->state_history[n_states * decoder->o_idx];

	in_sym  = malloc(sizeof(sbit_t) * code->N);

	i_idx = 0;
	p_idx = decoder->p_idx;

	/* Scan the treillis */
	for (i=0; i<code->K-1; i++)
	{
		/* Reset next accumulated error */
		for (s=0; s<n_states; s++) {
			ae_next[s] = MAX_AE;
		}

		/* Get input */
		if (code->puncture) {
			/* Hard way ... */
			for (j=0; j<code->N; j++) {
				int idx = ((decoder->o_idx + i) * code->N) + j;
				if (idx == code->puncture[p_idx]) {
					in_sym[j] = 0;	/* Undefined */
					p_idx++;
				} else {
					in_sym[j] = input[i_idx];
					i_idx++;
				}
			}
		} else {
			/* Easy, just copy N bits */
			memcpy(in_sym, &input[i_idx], code->N);
			i_idx += code->N;
		}

		/* Scan all state */
		for (s=0; s<n_states; s++)
		{
			int nae, ov, e;
			uint8_t m;

			/* Next output and state */
			uint8_t out;
			uint8_t state;

			if (code->next_term_output) {
				out   = code->next_term_output[s];
				state = code->next_term_state[s];
			} else {
				out   = code->next_output[s][0];
				state = code->next_state[s][0];
			}

			/* New error for this path */
			nae = ae[s];			/* start from last error */
			m = 1 << (code->N - 1);		/* mask for 'out' bit selection */

			for (j=0; j<code->N; j++) {
				int is = (int)in_sym[j];
				if (is) {
					ov = (out & m) ? -127 : 127; /* sbit_t value for it */
					e = is - ov;                 /* raw error for this bit */
					nae += (e * e) >> 9;         /* acc the squared/scaled value */
				}
				m >>= 1;                     /* next mask bit */
			}

			/* Is it survivor ? */
			if (ae_next[state] > nae) {
				ae_next[state] = nae;
				state_history[(n_states * i) + state] = s;
			}
		}

		/* Copy accumulated error */
		memcpy(ae, ae_next, sizeof(unsigned int) * n_states);
	}

	/* Update decoder state */
	decoder->p_idx = p_idx;
	decoder->o_idx += code->K - 1;

	free(in_sym);
	return i_idx;
}

int
osmo_conv_decode_get_output(struct osmo_conv_decoder *decoder,
                            ubit_t *output, int has_flush, int end_state)
{
	const struct osmo_conv_code *code = decoder->code;

	int min_ae;
	uint8_t min_state, cur_state;
	int i, s, n;

	uint8_t *sh_ptr;

	/* End state ? */
	if (end_state < 0) {
		/* Find state with least error */
		min_ae = MAX_AE;
		min_state = 0xff;

		for (s=0; s<decoder->n_states; s++)
		{
			if (decoder->ae[s] < min_ae) {
				min_ae = decoder->ae[s];
				min_state = s;
			}
		}

		if (min_state == 0xff)
			return -1;
	} else {
		min_state = (uint8_t) end_state;
		min_ae = decoder->ae[end_state];
	}

	/* Traceback */
	cur_state = min_state;

	n = decoder->o_idx;

	sh_ptr = &decoder->state_history[decoder->n_states * (n-1)];

		/* No output for the K-1 termination input bits */
	if (has_flush) {
		for (i=0; i<code->K-1; i++) {
			cur_state = sh_ptr[cur_state];
			sh_ptr -= decoder->n_states;
		}
		n -= code->K - 1;
	}

		/* Generate output backward */
	for (i=n-1; i>=0; i--)
	{
		min_state = cur_state;
		cur_state = sh_ptr[cur_state];

		sh_ptr -= decoder->n_states;

		if (code->next_state[cur_state][0] == min_state)
			output[i] = 0;
		else
			output[i] = 1;
	}

	return min_ae;
}

/*! All-in-one convolutional decoding function
 *  \param[in] code description of convolutional code to be used
 *  \param[in] input array of soft bits (coded)
 *  \param[out] output array of unpacked bits (decoded)
 *
 * This is an all-in-one function, taking care of
 * \ref osmo_conv_decode_init, \ref osmo_conv_decode_scan,
 * \ref osmo_conv_decode_flush, \ref osmo_conv_decode_get_output and
 * \ref osmo_conv_decode_deinit.
 */
int
osmo_conv_decode(const struct osmo_conv_code *code,
                 const sbit_t *input, ubit_t *output)
{
	struct osmo_conv_decoder decoder;
	int rv, l;

	/* Use accelerated implementation for supported codes */
	if ((code->N <= 4) && ((code->K == 5) || (code->K == 7)))
		return osmo_conv_decode_acc(code, input, output);

	osmo_conv_decode_init(&decoder, code, 0, 0);

	if (code->term == CONV_TERM_TAIL_BITING) {
		osmo_conv_decode_scan(&decoder, input, code->len);
		osmo_conv_decode_rewind(&decoder);
	}

	l = osmo_conv_decode_scan(&decoder, input, code->len);

	if (code->term == CONV_TERM_FLUSH)
		osmo_conv_decode_flush(&decoder, &input[l]);

	rv = osmo_conv_decode_get_output(&decoder, output,
		code->term == CONV_TERM_FLUSH,		/* has_flush */
		code->term == CONV_TERM_FLUSH ? 0 : -1	/* end_state */
	);

	osmo_conv_decode_deinit(&decoder);

	return rv;
}

/*! @} */
