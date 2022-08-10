/*! \file conv_acc.c
 * Accelerated Viterbi decoder implementation. */
/*
 * Copyright (C) 2013, 2014 Thomas Tsou <tom@tsou.cc>
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

#include <stdlib.h>
#include <string.h>
#include <errno.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#define __attribute__(_arg_)

#include <osmocom/core/conv.h>

#define BIT2NRZ(REG,N)	(((REG >> N) & 0x01) * 2 - 1) * -1
#define NUM_STATES(K)	(K == 7 ? 64 : 16)

#define INIT_POINTERS(simd) \
{ \
	osmo_conv_metrics_k5_n2 = osmo_conv_##simd##_metrics_k5_n2; \
	osmo_conv_metrics_k5_n3 = osmo_conv_##simd##_metrics_k5_n3; \
	osmo_conv_metrics_k5_n4 = osmo_conv_##simd##_metrics_k5_n4; \
	osmo_conv_metrics_k7_n2 = osmo_conv_##simd##_metrics_k7_n2; \
	osmo_conv_metrics_k7_n3 = osmo_conv_##simd##_metrics_k7_n3; \
	osmo_conv_metrics_k7_n4 = osmo_conv_##simd##_metrics_k7_n4; \
	vdec_malloc = &osmo_conv_##simd##_vdec_malloc; \
	vdec_free = &osmo_conv_##simd##_vdec_free; \
}

static int init_complete = 0;

__attribute__ ((visibility("hidden"))) int avx2_supported = 0;
__attribute__ ((visibility("hidden"))) int ssse3_supported = 0;
__attribute__ ((visibility("hidden"))) int sse41_supported = 0;

/**
 * These pointers are being initialized at runtime by the
 * osmo_conv_init() depending on supported SIMD extensions.
 */
static int16_t *(*vdec_malloc)(size_t n);
static void (*vdec_free)(int16_t *ptr);

void (*osmo_conv_metrics_k5_n2)(const int8_t *seq,
	const int16_t *out, int16_t *sums, int16_t *paths, int norm);
void (*osmo_conv_metrics_k5_n3)(const int8_t *seq,
	const int16_t *out, int16_t *sums, int16_t *paths, int norm);
void (*osmo_conv_metrics_k5_n4)(const int8_t *seq,
	const int16_t *out, int16_t *sums, int16_t *paths, int norm);
void (*osmo_conv_metrics_k7_n2)(const int8_t *seq,
	const int16_t *out, int16_t *sums, int16_t *paths, int norm);
void (*osmo_conv_metrics_k7_n3)(const int8_t *seq,
	const int16_t *out, int16_t *sums, int16_t *paths, int norm);
void (*osmo_conv_metrics_k7_n4)(const int8_t *seq,
	const int16_t *out, int16_t *sums, int16_t *paths, int norm);

/* Forward malloc wrappers */
int16_t *osmo_conv_gen_vdec_malloc(size_t n);
void osmo_conv_gen_vdec_free(int16_t *ptr);

#if defined(HAVE_SSSE3)
int16_t *osmo_conv_sse_vdec_malloc(size_t n);
void osmo_conv_sse_vdec_free(int16_t *ptr);
#endif

#if defined(HAVE_SSSE3) && defined(HAVE_AVX2)
int16_t *osmo_conv_sse_avx_vdec_malloc(size_t n);
void osmo_conv_sse_avx_vdec_free(int16_t *ptr);
#endif

/* Forward Metric Units */
void osmo_conv_gen_metrics_k5_n2(const int8_t *seq, const int16_t *out,
	int16_t *sums, int16_t *paths, int norm);
void osmo_conv_gen_metrics_k5_n3(const int8_t *seq, const int16_t *out,
	int16_t *sums, int16_t *paths, int norm);
void osmo_conv_gen_metrics_k5_n4(const int8_t *seq, const int16_t *out,
	int16_t *sums, int16_t *paths, int norm);
void osmo_conv_gen_metrics_k7_n2(const int8_t *seq, const int16_t *out,
	int16_t *sums, int16_t *paths, int norm);
void osmo_conv_gen_metrics_k7_n3(const int8_t *seq, const int16_t *out,
	int16_t *sums, int16_t *paths, int norm);
void osmo_conv_gen_metrics_k7_n4(const int8_t *seq, const int16_t *out,
	int16_t *sums, int16_t *paths, int norm);

#if defined(HAVE_SSSE3)
void osmo_conv_sse_metrics_k5_n2(const int8_t *seq, const int16_t *out,
	int16_t *sums, int16_t *paths, int norm);
void osmo_conv_sse_metrics_k5_n3(const int8_t *seq, const int16_t *out,
	int16_t *sums, int16_t *paths, int norm);
void osmo_conv_sse_metrics_k5_n4(const int8_t *seq, const int16_t *out,
	int16_t *sums, int16_t *paths, int norm);
void osmo_conv_sse_metrics_k7_n2(const int8_t *seq, const int16_t *out,
	int16_t *sums, int16_t *paths, int norm);
void osmo_conv_sse_metrics_k7_n3(const int8_t *seq, const int16_t *out,
	int16_t *sums, int16_t *paths, int norm);
void osmo_conv_sse_metrics_k7_n4(const int8_t *seq, const int16_t *out,
	int16_t *sums, int16_t *paths, int norm);
#endif

#if defined(HAVE_SSSE3) && defined(HAVE_AVX2)
void osmo_conv_sse_avx_metrics_k5_n2(const int8_t *seq, const int16_t *out,
	int16_t *sums, int16_t *paths, int norm);
void osmo_conv_sse_avx_metrics_k5_n3(const int8_t *seq, const int16_t *out,
	int16_t *sums, int16_t *paths, int norm);
void osmo_conv_sse_avx_metrics_k5_n4(const int8_t *seq, const int16_t *out,
	int16_t *sums, int16_t *paths, int norm);
void osmo_conv_sse_avx_metrics_k7_n2(const int8_t *seq, const int16_t *out,
	int16_t *sums, int16_t *paths, int norm);
void osmo_conv_sse_avx_metrics_k7_n3(const int8_t *seq, const int16_t *out,
	int16_t *sums, int16_t *paths, int norm);
void osmo_conv_sse_avx_metrics_k7_n4(const int8_t *seq, const int16_t *out,
	int16_t *sums, int16_t *paths, int norm);
#endif

/* Trellis State
 * state - Internal lshift register value
 * prev  - Register values of previous 0 and 1 states
 */
struct vstate {
	unsigned state;
	unsigned prev[2];
};

/* Trellis Object
 * num_states - Number of states in the trellis
 * sums       - Accumulated path metrics
 * outputs    - Trellis output values
 * vals       - Input value that led to each state
 */
struct vtrellis {
	int num_states;
	int16_t *sums;
	int16_t *outputs;
	uint8_t *vals;
};

/* Viterbi Decoder
 * n         - Code order
 * k         - Constraint length
 * len       - Horizontal length of trellis
 * recursive - Set to '1' if the code is recursive
 * intrvl    - Normalization interval
 * trellis   - Trellis object
 * paths     - Trellis paths
 */
struct vdecoder {
	int n;
	int k;
	int len;
	int recursive;
	int intrvl;
	struct vtrellis trellis;
	int16_t **paths;

	void (*metric_func)(const int8_t *, const int16_t *,
		int16_t *, int16_t *, int);
};

/* Accessor calls */
static inline int conv_code_recursive(const struct osmo_conv_code *code)
{
	return code->next_term_output ? 1 : 0;
}

/* Left shift and mask for finding the previous state */
static unsigned vstate_lshift(unsigned reg, int k, int val)
{
	unsigned mask;

	if (k == 5)
		mask = 0x0e;
	else if (k == 7)
		mask = 0x3e;
	else
		mask = 0;

	return ((reg << 1) & mask) | val;
}

/* Bit endian manipulators */
static inline unsigned bitswap2(unsigned v)
{
	return ((v & 0x02) >> 1) | ((v & 0x01) << 1);
}

static inline unsigned bitswap3(unsigned v)
{
	return ((v & 0x04) >> 2) | ((v & 0x02) >> 0) |
		((v & 0x01) << 2);
}

static inline unsigned bitswap4(unsigned v)
{
	return ((v & 0x08) >> 3) | ((v & 0x04) >> 1) |
		((v & 0x02) << 1) | ((v & 0x01) << 3);
}

static inline unsigned bitswap5(unsigned v)
{
	return ((v & 0x10) >> 4) | ((v & 0x08) >> 2) | ((v & 0x04) >> 0) |
		((v & 0x02) << 2) | ((v & 0x01) << 4);
}

static inline unsigned bitswap6(unsigned v)
{
	return ((v & 0x20) >> 5) | ((v & 0x10) >> 3) | ((v & 0x08) >> 1) |
		((v & 0x04) << 1) | ((v & 0x02) << 3) | ((v & 0x01) << 5);
}

static unsigned bitswap(unsigned v, unsigned n)
{
	switch (n) {
	case 1:
		return v;
	case 2:
		return bitswap2(v);
	case 3:
		return bitswap3(v);
	case 4:
		return bitswap4(v);
	case 5:
		return bitswap5(v);
	case 6:
		return bitswap6(v);
	default:
		return 0;
	}
}

/* Generate non-recursive state output from generator state table
 * Note that the shift register moves right (i.e. the most recent bit is
 * shifted into the register at k-1 bit of the register), which is typical
 * textbook representation. The API transition table expects the most recent
 * bit in the low order bit, or left shift. A bitswap operation is required
 * to accommodate the difference.
 */
static unsigned gen_output(struct vstate *state, int val,
	const struct osmo_conv_code *code)
{
	unsigned out, prev;

	prev = bitswap(state->prev[0], code->K - 1);
	out = code->next_output[prev][val];
	out = bitswap(out, code->N);

	return out;
}

/* Populate non-recursive trellis state
 * For a given state defined by the k-1 length shift register, find the
 * value of the input bit that drove the trellis to that state. Also
 * generate the N outputs of the generator polynomial at that state.
 */
static int gen_state_info(uint8_t *val, unsigned reg,
	int16_t *output, const struct osmo_conv_code *code)
{
	int i;
	unsigned out;
	struct vstate state;

	/* Previous '0' state */
	state.state = reg;
	state.prev[0] = vstate_lshift(reg, code->K, 0);
	state.prev[1] = vstate_lshift(reg, code->K, 1);

	*val = (reg >> (code->K - 2)) & 0x01;

	/* Transition output */
	out = gen_output(&state, *val, code);

	/* Unpack to NRZ */
	for (i = 0; i < code->N; i++)
		output[i] = BIT2NRZ(out, i);

	return 0;
}

/* Generate recursive state output from generator state table */
static unsigned gen_recursive_output(struct vstate *state,
	uint8_t *val, unsigned reg,
	const struct osmo_conv_code *code, int pos)
{
	int val0, val1;
	unsigned out, prev;

	/* Previous '0' state */
	prev = vstate_lshift(reg, code->K, 0);
	prev = bitswap(prev, code->K - 1);

	/* Input value */
	val0 = (reg >> (code->K - 2)) & 0x01;
	val1 = (code->next_term_output[prev] >> pos) & 0x01;
	*val = val0 == val1 ? 0 : 1;

	/* Wrapper for osmocom state access */
	prev = bitswap(state->prev[0], code->K - 1);

	/* Compute the transition output */
	out = code->next_output[prev][*val];
	out = bitswap(out, code->N);

	return out;
}

/* Populate recursive trellis state
 * The bit position of the systematic bit is not explicitly marked by the
 * API, so it must be extracted from the generator table. Otherwise,
 * populate the trellis similar to the non-recursive version.
 * Non-systematic recursive codes are not supported.
 */
static int gen_recursive_state_info(uint8_t *val,
	unsigned reg, int16_t *output, const struct osmo_conv_code *code)
{
	int i, j, pos = -1;
	int ns = NUM_STATES(code->K);
	unsigned out;
	struct vstate state;

	/* Previous '0' and '1' states */
	state.state = reg;
	state.prev[0] = vstate_lshift(reg, code->K, 0);
	state.prev[1] = vstate_lshift(reg, code->K, 1);

	/* Find recursive bit location */
	for (i = 0; i < code->N; i++) {
		for (j = 0; j < ns; j++) {
			if ((code->next_output[j][0] >> i) & 0x01)
				break;
		}

		if (j == ns) {
			pos = i;
			break;
		}
	}

	/* Non-systematic recursive code not supported */
	if (pos < 0)
		return -EPROTO;

	/* Transition output */
	out = gen_recursive_output(&state, val, reg, code, pos);

	/* Unpack to NRZ */
	for (i = 0; i < code->N; i++)
		output[i] = BIT2NRZ(out, i);

	return 0;
}

/* Release the trellis */
static void free_trellis(struct vtrellis *trellis)
{
	if (!trellis)
		return;

	vdec_free(trellis->outputs);
	vdec_free(trellis->sums);
	free(trellis->vals);
}

/* Initialize the trellis object
 * Initialization consists of generating the outputs and output value of a
 * given state. Due to trellis symmetry and anti-symmetry, only one of the
 * transition paths is utilized by the butterfly operation in the forward
 * recursion, so only one set of N outputs is required per state variable.
 */
static int generate_trellis(struct vdecoder *dec,
	const struct osmo_conv_code *code)
{
	struct vtrellis *trellis = &dec->trellis;
	int16_t *outputs;
	int i, rc;

	int ns = NUM_STATES(code->K);
	int olen = (code->N == 2) ? 2 : 4;

	trellis->num_states = ns;
	trellis->sums =	vdec_malloc(ns);
	trellis->outputs = vdec_malloc(ns * olen);
	trellis->vals = (uint8_t *) malloc(ns * sizeof(uint8_t));

	if (!trellis->sums || !trellis->outputs || !trellis->vals) {
		rc = -ENOMEM;
		goto fail;
	}

	/* Populate the trellis state objects */
	for (i = 0; i < ns; i++) {
		outputs = &trellis->outputs[olen * i];
		if (dec->recursive) {
			rc = gen_recursive_state_info(&trellis->vals[i],
				i, outputs, code);
		} else {
			rc = gen_state_info(&trellis->vals[i],
				i, outputs, code);
		}

		if (rc < 0)
			goto fail;

		/* Set accumulated path metrics to zero */
		trellis->sums[i] = 0;
	}

	/**
	 * For termination other than tail-biting, initialize the zero state
	 * as the encoder starting state. Initialize with the maximum
	 * accumulated sum at length equal to the constraint length.
	 */
	if (code->term != CONV_TERM_TAIL_BITING)
		trellis->sums[0] = INT8_MAX * code->N * code->K;

	return 0;

fail:
	free_trellis(trellis);
	return rc;
}

static void _traceback(struct vdecoder *dec,
	unsigned state, uint8_t *out, int len)
{
	int i;
	unsigned path;

	for (i = len - 1; i >= 0; i--) {
		path = dec->paths[i][state] + 1;
		out[i] = dec->trellis.vals[state];
		state = vstate_lshift(state, dec->k, path);
	}
}

static void _traceback_rec(struct vdecoder *dec,
	unsigned state, uint8_t *out, int len)
{
	int i;
	unsigned path;

	for (i = len - 1; i >= 0; i--) {
		path = dec->paths[i][state] + 1;
		out[i] = path ^ dec->trellis.vals[state];
		state = vstate_lshift(state, dec->k, path);
	}
}

/* Traceback and generate decoded output
 * Find the largest accumulated path metric at the final state except for
 * the zero terminated case, where we assume the final state is always zero.
 */
static int traceback(struct vdecoder *dec, uint8_t *out, int term, int len)
{
	int i, sum, max = -1;
	unsigned path, state = 0;

	if (term != CONV_TERM_FLUSH) {
		for (i = 0; i < dec->trellis.num_states; i++) {
			sum = dec->trellis.sums[i];
			if (sum > max) {
				max = sum;
				state = i;
			}
		}

		if (max < 0)
			return -EPROTO;
	}

	for (i = dec->len - 1; i >= len; i--) {
		path = dec->paths[i][state] + 1;
		state = vstate_lshift(state, dec->k, path);
	}

	if (dec->recursive)
		_traceback_rec(dec, state, out, len);
	else
		_traceback(dec, state, out, len);

	return 0;
}

/* Release decoder object */
static void vdec_deinit(struct vdecoder *dec)
{
	if (!dec)
		return;

	free_trellis(&dec->trellis);

	if (dec->paths != NULL) {
		vdec_free(dec->paths[0]);
		free(dec->paths);
	}
}

/* Initialize decoder object with code specific params
 * Subtract the constraint length K on the normalization interval to
 * accommodate the initialization path metric at state zero.
 */
static int vdec_init(struct vdecoder *dec, const struct osmo_conv_code *code)
{
	int i, ns, rc;

	ns = NUM_STATES(code->K);

	dec->n = code->N;
	dec->k = code->K;
	dec->recursive = conv_code_recursive(code);
	dec->intrvl = INT16_MAX / (dec->n * INT8_MAX) - dec->k;

	if (dec->k == 5) {
		switch (dec->n) {
		case 2:
			dec->metric_func = osmo_conv_metrics_k5_n2;
			break;
		case 3:
			dec->metric_func = osmo_conv_metrics_k5_n3;
			break;
		case 4:
			dec->metric_func = osmo_conv_metrics_k5_n4;
			break;
		default:
			return -EINVAL;
		}
	} else if (dec->k == 7) {
		switch (dec->n) {
		case 2:
			dec->metric_func = osmo_conv_metrics_k7_n2;
			break;
		case 3:
			dec->metric_func = osmo_conv_metrics_k7_n3;
			break;
		case 4:
			dec->metric_func = osmo_conv_metrics_k7_n4;
			break;
		default:
			return -EINVAL;
		}
	} else {
		return -EINVAL;
	}

	if (code->term == CONV_TERM_FLUSH)
		dec->len = code->len + code->K - 1;
	else
		dec->len = code->len;

	rc = generate_trellis(dec, code);
	if (rc)
		return rc;

	dec->paths = (int16_t **) malloc(sizeof(int16_t *) * dec->len);
	if (!dec->paths)
		goto enomem;

	dec->paths[0] = vdec_malloc(ns * dec->len);
	if (!dec->paths[0])
		goto enomem;

	for (i = 1; i < dec->len; i++)
		dec->paths[i] = &dec->paths[0][i * ns];

	return 0;

enomem:
	vdec_deinit(dec);
	return -ENOMEM;
}

/* Depuncture sequence with nagative value terminated puncturing matrix */
static int depuncture(const int8_t *in, const int *punc, int8_t *out, int len)
{
	int i, n = 0, m = 0;

	for (i = 0; i < len; i++) {
		if (i == punc[n]) {
			out[i] = 0;
			n++;
			continue;
		}

		out[i] = in[m++];
	}

	return 0;
}

/* Forward trellis recursion
 * Generate branch metrics and path metrics with a combined function. Only
 * accumulated path metric sums and path selections are stored. Normalize on
 * the interval specified by the decoder.
 */
static void forward_traverse(struct vdecoder *dec, const int8_t *seq)
{
	int i;

	for (i = 0; i < dec->len; i++) {
		dec->metric_func(&seq[dec->n * i],
			dec->trellis.outputs,
			dec->trellis.sums,
			dec->paths[i],
			!(i % dec->intrvl));
	}
}

/* Convolutional decode with a decoder object
 * Initial puncturing run if necessary followed by the forward recursion.
 * For tail-biting perform a second pass before running the backward
 * traceback operation.
 */
static int conv_decode(struct vdecoder *dec, const int8_t *seq,
	const int *punc, uint8_t *out, int len, int term)
{
	//int8_t depunc[dec->len * dec->n]; //!! this isn't portable, in strict C you can't use size of an array that is not known at compile time
	int8_t * depunc = malloc(sizeof(int8_t)*dec->len * dec->n);

	
	if (punc) {
		depuncture(seq, punc, depunc, dec->len * dec->n);
		seq = depunc;
	}

	/* Propagate through the trellis with interval normalization */
	forward_traverse(dec, seq);

	if (term == CONV_TERM_TAIL_BITING)
		forward_traverse(dec, seq);
	
	free(depunc);
	return traceback(dec, out, term, len);
}

static void osmo_conv_init(void)
{
	init_complete = 1;

#ifdef HAVE___BUILTIN_CPU_SUPPORTS
	/* Detect CPU capabilities */
	#ifdef HAVE_AVX2
		avx2_supported = __builtin_cpu_supports("avx2");
	#endif

	#ifdef HAVE_SSSE3
		ssse3_supported = __builtin_cpu_supports("ssse3");
	#endif

	#ifdef HAVE_SSE4_1
		sse41_supported = __builtin_cpu_supports("sse4.1");
	#endif
#endif

/**
 * Usage of curly braces is mandatory,
 * because we use multi-line define.
 */
#if defined(HAVE_SSSE3) && defined(HAVE_AVX2)
	if (ssse3_supported && avx2_supported) {
		INIT_POINTERS(sse_avx);
	} else if (ssse3_supported) {
		INIT_POINTERS(sse);
	} else {
		INIT_POINTERS(gen);
	}
#elif defined(HAVE_SSSE3)
	if (ssse3_supported) {
		INIT_POINTERS(sse);
	} else {
		INIT_POINTERS(gen);
	}
#else
	INIT_POINTERS(gen);
#endif
}

/* All-in-one Viterbi decoding  */
int osmo_conv_decode_acc(const struct osmo_conv_code *code,
	const sbit_t *input, ubit_t *output)
{
	int rc;
	struct vdecoder dec;

	if (!init_complete)
		osmo_conv_init();

	if ((code->N < 2) || (code->N > 4) || (code->len < 1) ||
		((code->K != 5) && (code->K != 7)))
		return -EINVAL;

	rc = vdec_init(&dec, code);
	if (rc)
		return rc;

	rc = conv_decode(&dec, input, code->puncture,
		output, code->len, code->term);

	vdec_deinit(&dec);

	return rc;
}
