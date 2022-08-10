/* -*- c++ -*- */
/* @file
 * @author (C) 2015 by Roman Khassraf <rkhassraf@gmail.com>
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

#ifndef INCLUDED_GSM_DUMMY_BURST_FILTER_H
#define INCLUDED_GSM_DUMMY_BURST_FILTER_H

#include <grgsm/api.h>
#include <gnuradio/block.h>
#include <grgsm/flow_control/common.h>

namespace gr {
  namespace gsm {

    /*!
     * \brief <+description of block+>
     * \ingroup gsm
     *
     */
    class GRGSM_API dummy_burst_filter : virtual public gr::block
    {
     public:
      typedef boost::shared_ptr<dummy_burst_filter> sptr;

      /*!
       * \brief Return a shared_ptr to a new instance of grgsm::dummy_burst_filter.
       *
       * To avoid accidental use of raw pointers, grgsm::dummy_burst_filter's
       * constructor is in a private implementation
       * class. grgsm::dummy_burst_filter::make is the public interface for
       * creating new instances.
       */
      static sptr make();

      /* External API */
      /* Filtering policy */
      virtual filter_policy get_policy(void) = 0;
      virtual filter_policy set_policy(filter_policy policy) = 0;
    };
  } // namespace gsm
} // namespace gr

#endif /* INCLUDED_GSM_DUMMY_BURST_FILTER_H */
