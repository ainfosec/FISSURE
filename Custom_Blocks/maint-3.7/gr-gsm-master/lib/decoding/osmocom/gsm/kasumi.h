/*! \file kasumi.h
 * KASUMI header.
 *
 * See kasumi.c for details
 * The parameters are described in TS 135 202.
 */

#pragma once

#include <stdint.h>

/*! Single iteration of KASUMI cipher
 *  \param[in] P Block, 64 bits to be processed in this round
 *  \param[in] KLi1 Expanded subkeys
 *  \param[in] KLi2 Expanded subkeys
 *  \param[in] KOi1 Expanded subkeys
 *  \param[in] KOi2 Expanded subkeys
 *  \param[in] KOi3 Expanded subkeys
 *  \param[in] KIi1 Expanded subkeys
 *  \param[in] KIi2 Expanded subkeys
 *  \param[in] KIi3 Expanded subkeys
 *  \returns processed block of 64 bits
 */
uint64_t _kasumi(uint64_t P, const uint16_t *KLi1, const uint16_t *KLi2, const uint16_t *KOi1, const uint16_t *KOi2, const uint16_t *KOi3, const uint16_t *KIi1, const uint16_t *KIi2, const uint16_t *KIi3);

/*! Implementation of the KGCORE algorithm (used by A5/3, A5/4, GEA3, GEA4 and ECSD)
 *  \param[in] CA
 *  \param[in] cb
 *  \param[in] cc
 *  \param[in] cd
 *  \param[in] ck 8-bytes long key
 *  \param[out] co cl-dependent
 *  \param[in] cl
 */
void _kasumi_kgcore(uint8_t CA, uint8_t cb, uint32_t cc, uint8_t cd, const uint8_t *ck, uint8_t *co, uint16_t cl);

/*! Expand key into set of subkeys - see TS 135 202 for details
 *  \param[in] key (128 bits) as array of bytes
 *  \param[out] KLi1 Expanded subkeys
 *  \param[out] KLi2 Expanded subkeys
 *  \param[out] KOi1 Expanded subkeys
 *  \param[out] KOi2 Expanded subkeys
 *  \param[out] KOi3 Expanded subkeys
 *  \param[out] KIi1 Expanded subkeys
 *  \param[out] KIi2 Expanded subkeys
 *  \param[out] KIi3 Expanded subkeys
 */
void _kasumi_key_expand(const uint8_t *key, uint16_t *KLi1, uint16_t *KLi2, uint16_t *KOi1, uint16_t *KOi2, uint16_t *KOi3, uint16_t *KIi1, uint16_t *KIi2, uint16_t *KIi3);
