/* -*- c++ -*- */
/*
 * @file
 * @author (C) 2017 by Roman Khassraf <rkhassraf@gmail.com>
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


#ifndef INCLUDED_GSM_COLLECT_SYSTEM_INFO_H
#define INCLUDED_GSM_COLLECT_SYSTEM_INFO_H

#include <grgsm/api.h>
#include <gnuradio/block.h>
#include <vector>

namespace gr {
  namespace gsm {

    /*!
     * \brief <+description of block+>
     * \ingroup gsm
     *
     */
    class GRGSM_API collect_system_info : virtual public gr::block
    {
     public:
      typedef boost::shared_ptr<collect_system_info> sptr;

      /*!
       * \brief Return a shared_ptr to a new instance of gsm::collect_system_info.
       *
       * To avoid accidental use of raw pointers, gsm::collect_system_info's
       * constructor is in a private implementation
       * class. gsm::collect_system_info::make is the public interface for
       * creating new instances.
       */
      static sptr make();
      virtual std::vector<int> get_framenumbers() = 0;
      virtual std::vector<std::string> get_system_information_type() = 0;
      virtual std::vector<std::string> get_data() = 0;
    };
  } // namespace gsm
} // namespace gr

#endif /* INCLUDED_GSM_COLLECT_SYSTEM_INFO_H */
