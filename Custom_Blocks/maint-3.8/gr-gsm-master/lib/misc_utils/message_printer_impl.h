/* -*- c++ -*- */
/*
 * @file
 * @author (C) 2014 by Piotr Krysik <ptrkrysik@gmail.com>
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

#ifndef INCLUDED_GSM_MESSAGE_PRINTER_IMPL_H
#define INCLUDED_GSM_MESSAGE_PRINTER_IMPL_H

#include <grgsm/misc_utils/message_printer.h>

namespace gr {
  namespace gsm {

    class message_printer_impl : public message_printer
    {
     private:
      void message_print(pmt::pmt_t msg);
      pmt::pmt_t d_prepend_string;
      bool d_prepend_fnr;
      bool d_prepend_frame_count;
      bool d_print_gsmtap_header;
     public:
      message_printer_impl(pmt::pmt_t prepend_string, bool prepend_fnr=false,
        bool prepend_frame_count=false, bool print_gsmtap_header=false);
      ~message_printer_impl();
    };

  } // namespace gsm
} // namespace gr

#endif /* INCLUDED_GSM_MESSAGE_PRINTER_IMPL_H */

