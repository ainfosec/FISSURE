/* -*- c++ -*- */
/* @file
 * @author Piotr Krysik <ptrkrysik@gmail.com>
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


#ifndef INCLUDED_GSM_FN_TIME_H
#define INCLUDED_GSM_FN_TIME_H

#include <gsm/api.h>
#include <stdint.h>
#include <utility>

namespace gr {
  namespace gsm {
   
    /**
     * Computes difference between reference frame number
     * and a second frame number. 
     * @param  fn_ref    reference frame number modulo GSM_HYPER_FRAME
     * @param  fn        second frame number modulo GSM_HYPER_FRAME
     * @param  time_ref  precise timestamp of the first sample in the fn_ref
     * @param  time_hint coarse time for fn that is used as a hint to avoid
     *                   ambiguities caused by modulo operation applied to
     *                   frame numbers
     * @return           difference between fn_ref and fn
     */
     typedef std::pair<unsigned long long, double> time_format;
     
    GSM_API time_format fn_time_delta_cpp(uint32_t fn_ref, time_format time_ref, uint32_t fn_x,
      time_format time_hint, uint32_t ts_num, uint32_t ts_ref);

  } // namespace gsm
} // namespace gr

#endif /* INCLUDED_GSM_FN_TIME_H */

