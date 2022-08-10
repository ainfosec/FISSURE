/* -*- c++ -*- */
/* 
 * Copyright 2014 Jared Boone <jared@sharebrained.com>.
 * 
 * This is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3, or (at your option)
 * any later version.
 * 
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this software; see the file COPYING.  If not, write to
 * the Free Software Foundation, Inc., 51 Franklin Street,
 * Boston, MA 02110-1301, USA.
 */

#ifndef INCLUDED_TPMS_ASK_ENV_IMPL_H
#define INCLUDED_TPMS_ASK_ENV_IMPL_H

#include <tpms/ask_env.h>

namespace gr {
  namespace tpms {

    class ask_env_impl : public ask_env
    {
     private:
      float d_max;
      float d_min;
      float d_alpha;

     public:
      ask_env_impl(float alpha);
      ~ask_env_impl();

      void set_alpha(float alpha);
      float alpha();

      int work(int noutput_items,
	       gr_vector_const_void_star &input_items,
	       gr_vector_void_star &output_items);
    };

  } // namespace tpms
} // namespace gr

#endif /* INCLUDED_TPMS_ASK_ENV_IMPL_H */

