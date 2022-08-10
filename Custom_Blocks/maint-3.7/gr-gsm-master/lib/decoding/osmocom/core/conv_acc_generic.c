/*! \file conv_acc_generic.c
 * Accelerated Viterbi decoder implementation
 * for generic architectures without SSE support. */
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
#include <stdint.h>
#include <string.h>

#define __attribute__(_arg_)

/* Add-Compare-Select (ACS-Butterfly)
 * Compute 4 accumulated path metrics and 4 path selections. Note that path
 * selections are store as -1 and 0 rather than 0 and 1. This is to match
 * the output format of the SSE packed compare instruction 'pmaxuw'.
 */

static void acs_butterfly(int state, int num_states,
	int16_t metric, int16_t *sum,
	int16_t *new_sum, int16_t *path)
{
	int state0, state1;
	int sum0, sum1, sum2, sum3;

	state0 = *(sum + (2 * state + 0));
	state1 = *(sum + (2 * state + 1));

	sum0 = state0 + metric;
	sum1 = state1 - metric;
	sum2 = state0 - metric;
	sum3 = state1 + metric;

	if (sum0 >= sum1) {
		*new_sum = sum0;
		*path = -1;
	} else {
		*new_sum = sum1;
		*path = 0;
	}

	if (sum2 >= sum3) {
		*(new_sum + num_states / 2) = sum2;
		*(path + num_states / 2) = -1;
	} else {
		*(new_sum + num_states / 2) = sum3;
		*(path + num_states / 2) = 0;
	}
}

/* Branch metrics unit N=2 */
static void gen_branch_metrics_n2(int num_states, const int8_t *seq,
	const int16_t *out, int16_t *metrics)
{
	int i;

	for (i = 0; i < num_states / 2; i++) {
		metrics[i] = seq[0] * out[2 * i + 0] +
			seq[1] * out[2 * i + 1];
	}
}

/* Branch metrics unit N=3 */
static void gen_branch_metrics_n3(int num_states, const int8_t *seq,
	const int16_t *out, int16_t *metrics)
{
	int i;

	for (i = 0; i < num_states / 2; i++) {
		metrics[i] = seq[0] * out[4 * i + 0] +
			seq[1] * out[4 * i + 1] +
			seq[2] * out[4 * i + 2];
	}
}

/* Branch metrics unit N=4 */
static void gen_branch_metrics_n4(int num_states, const int8_t *seq,
	const int16_t *out, int16_t *metrics)
{
	int i;

	for (i = 0; i < num_states / 2; i++) {
		metrics[i] = seq[0] * out[4 * i + 0] +
			seq[1] * out[4 * i + 1] +
			seq[2] * out[4 * i + 2] +
			seq[3] * out[4 * i + 3];
	}
}

/* Path metric unit */
static void gen_path_metrics(int num_states, int16_t *sums,
	int16_t *metrics, int16_t *paths, int norm)
{
	int i;
	int16_t min;
	int16_t * new_sums = malloc(sizeof(int16_t)*num_states);

	for (i = 0; i < num_states / 2; i++)
		acs_butterfly(i, num_states, metrics[i],
			sums, &new_sums[i], &paths[i]);

	if (norm) {
		min = new_sums[0];

		for (i = 1; i < num_states; i++)
			if (new_sums[i] < min)
				min = new_sums[i];

		for (i = 0; i < num_states; i++)
			new_sums[i] -= min;
	}
	
	memcpy(sums, new_sums, num_states * sizeof(int16_t));
	free(new_sums);

}

/* Not-aligned Memory Allocator */
__attribute__ ((visibility("hidden")))
int16_t *osmo_conv_gen_vdec_malloc(size_t n)
{
	return (int16_t *) malloc(sizeof(int16_t) * n);
}

__attribute__ ((visibility("hidden")))
void osmo_conv_gen_vdec_free(int16_t *ptr)
{
	free(ptr);
}

/* 16-state branch-path metrics units (K=5) */
__attribute__ ((visibility("hidden")))
void osmo_conv_gen_metrics_k5_n2(const int8_t *seq, const int16_t *out,
	int16_t *sums, int16_t *paths, int norm)
{
	int16_t metrics[8];

	gen_branch_metrics_n2(16, seq, out, metrics);
	gen_path_metrics(16, sums, metrics, paths, norm);
}

__attribute__ ((visibility("hidden")))
void osmo_conv_gen_metrics_k5_n3(const int8_t *seq, const int16_t *out,
	int16_t *sums, int16_t *paths, int norm)
{
	int16_t metrics[8];

	gen_branch_metrics_n3(16, seq, out, metrics);
	gen_path_metrics(16, sums, metrics, paths, norm);

}

__attribute__ ((visibility("hidden")))
void osmo_conv_gen_metrics_k5_n4(const int8_t *seq, const int16_t *out,
	int16_t *sums, int16_t *paths, int norm)
{
	int16_t metrics[8];

	gen_branch_metrics_n4(16, seq, out, metrics);
	gen_path_metrics(16, sums, metrics, paths, norm);

}

/* 64-state branch-path metrics units (K=7) */
__attribute__ ((visibility("hidden")))
void osmo_conv_gen_metrics_k7_n2(const int8_t *seq, const int16_t *out,
	int16_t *sums, int16_t *paths, int norm)
{
	int16_t metrics[32];

	gen_branch_metrics_n2(64, seq, out, metrics);
	gen_path_metrics(64, sums, metrics, paths, norm);

}

__attribute__ ((visibility("hidden")))
void osmo_conv_gen_metrics_k7_n3(const int8_t *seq, const int16_t *out,
	int16_t *sums, int16_t *paths, int norm)
{
	int16_t metrics[32];

	gen_branch_metrics_n3(64, seq, out, metrics);
	gen_path_metrics(64, sums, metrics, paths, norm);

}

__attribute__ ((visibility("hidden")))
void osmo_conv_gen_metrics_k7_n4(const int8_t *seq, const int16_t *out,
	int16_t *sums, int16_t *paths, int norm)
{
	int16_t metrics[32];

	gen_branch_metrics_n4(64, seq, out, metrics);
	gen_path_metrics(64, sums, metrics, paths, norm);
}
