/* -*- c++ -*- */
/*
 * @file
 * @author (C) 2017 by Vadim Yanitskiy <axilirator@gmail.com>
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
 */

#ifndef INCLUDED_GSM_FLOW_CONTROL_COMMON_H
#define INCLUDED_GSM_FLOW_CONTROL_COMMON_H

namespace gr {
  namespace gsm {

    enum filter_policy {
      FILTER_POLICY_DEFAULT,
      FILTER_POLICY_PASS_ALL,
      FILTER_POLICY_DROP_ALL,
    };

  } /* namespace gsm */
} /* namespace gr */

#endif
