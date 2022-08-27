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

#include <gsm/misc_utils/fn_time.h>
#include <gsm/misc_utils/time_spec.h>
#include <math.h>

#define GSM_HYPER_FRAME (26 * 51 * 2048)
#define GSM_SYM_RATE (13.0e6 / 48.0)

#define GSM_TS_PERIOD (156.25 / GSM_SYM_RATE)
#define GSM_FN_PERIOD (8 * GSM_TS_PERIOD)

namespace gr {
  namespace gsm {
    /**
     * Computes difference between two frame numbers modulo
     * GSM_HYPER_FRAME / 2. The result is correct if difference
     * between the frame numbers is not bigger than GSM_HYPER_FRAME / 2.
     * @param  fn1 first frame number
     * @param  fn2 second frame number
     * @return     computed difference
     */
    static int fnmod_delta(uint32_t fn1, uint32_t fn2)
    {
      int delta, h2;

      delta = (fn1 % GSM_HYPER_FRAME) - (fn2 % GSM_HYPER_FRAME);

      h2 = GSM_HYPER_FRAME / 2;

      if (delta >= h2) {
        delta -= GSM_HYPER_FRAME;
      } else if(delta < -h2) {
        delta += GSM_HYPER_FRAME;
      }

      return delta;
    }

    static int fn_time_diff_delta(uint32_t fn, uint32_t fn_ref,
      time_spec_t time_diff_hint)
    {
      int frames_diff, fn_delta;
      frames_diff = int(round(time_diff_hint.get_real_secs() / GSM_FN_PERIOD));
      fn_delta = fnmod_delta(fn, fn_ref + frames_diff) + frames_diff;

      return fn_delta;
    }

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
    time_format fn_time_delta_cpp(uint32_t fn_ref, time_format time_ref, uint32_t fn_x, 
      time_format time_hint, uint32_t ts_num, uint32_t ts_ref)
    {
      time_spec_t time_diff_hint = time_spec_t(time_hint.first, time_hint.second) - time_spec_t(time_ref.first, time_ref.second);
      int fn_delta = fn_time_diff_delta(fn_x, fn_ref, time_diff_hint);
      time_spec_t time_x_precise = fn_delta * GSM_FN_PERIOD + time_spec_t(time_ref.first, time_ref.second) + (static_cast<int>(ts_num) - static_cast<int>(ts_ref)) * GSM_TS_PERIOD;

      return time_format(time_x_precise.get_full_secs(), time_x_precise.get_frac_secs());
    }

  } /* namespace gsm */
} /* namespace gr */

