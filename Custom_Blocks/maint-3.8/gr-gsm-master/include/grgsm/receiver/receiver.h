/* -*- c++ -*- */
/*
 * @file
 * @author (C) 2014-2016 by Piotr Krysik <ptrkrysik@gmail.com>
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


#ifndef INCLUDED_GSM_RECEIVER_H
#define INCLUDED_GSM_RECEIVER_H

#include <grgsm/api.h>
#include <gnuradio/block.h>
#include <gnuradio/sync_block.h>
#include <vector>

namespace gr {
  namespace gsm {

    /*!
     * \brief <+description of block+>
     * \ingroup gsm
     *
     */
    class GRGSM_API receiver : virtual public sync_block
    {
     public:
      typedef boost::shared_ptr<receiver> sptr;

      /*!
       * \brief Return a shared_ptr to a new instance of gsm::receiver.
       *
       * To avoid accidental use of raw pointers, gsm::receiver's
       * constructor is in a private implementation
       * class. gsm::receiver::make is the public interface for
       * creating new instances.
       */
      static sptr make(int osr, const std::vector<int> &cell_allocation, const std::vector<int> &seq_nums, bool process_uplink=false);
      
      virtual void set_cell_allocation(const std::vector<int> &cell_allocation) = 0;
      virtual void set_tseq_nums(const std::vector<int> & tseq_nums) = 0;
      virtual void reset() = 0;
    };
   
  } // namespace gsm
} // namespace gr

#endif /* INCLUDED_GSM_RECEIVER_H */
 
