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

#ifndef INCLUDED_TPMS_ASK_ENV_H
#define INCLUDED_TPMS_ASK_ENV_H

#include <tpms/api.h>
#include <gnuradio/sync_block.h>

namespace gr {
  namespace tpms {

    /*!
     * \brief Tire Pressure Monitoring System
     * \ingroup tpms
     *
     */
    class TPMS_API ask_env : virtual public gr::sync_block
    {
     public:
      typedef boost::shared_ptr<ask_env> sptr;

      /*!
       * \class ask_env
       * \brief Bipolar envelope detection and scaling to +/- 1.0.
       * \param alpha Multiplicative ate at which envelope peaks decay.
       */
      static sptr make(float alpha);

      virtual void set_alpha(float var) = 0;
      virtual float alpha() = 0;
    };

  } // namespace tpms
} // namespace gr

#endif /* INCLUDED_TPMS_ASK_ENV_H */

