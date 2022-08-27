/* -*- c++ -*- */
/* @file
 * @author (C) 2016 by Piotr Krysik <ptrkrysik@gmail.com>
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


#ifndef INCLUDED_GSM_MSG_TO_TAG_H
#define INCLUDED_GSM_MSG_TO_TAG_H

#include <gsm/api.h>
#include <gnuradio/sync_block.h>

namespace gr {
  namespace gsm {

    /*!
     * \brief <+description of block+>
     * \ingroup grgsm
     *
     */
    class GSM_API msg_to_tag : virtual public gr::sync_block
    {
     public:
      typedef std::shared_ptr<msg_to_tag> sptr;
      /*!
       * \brief Return a shared_ptr to a new instance of grgsm::msg_to_tag.
       *
       * To avoid accidental use of raw pointers, grgsm::msg_to_tag's
       * constructor is in a private implementation
       * class. grgsm::msg_to_tag::make is the public interface for
       * creating new instances.
       */
      static sptr make();
    };

  } // namespace gsm
} // namespace gr

#endif /* INCLUDED_GSM_MSG_TO_TAG_H */

