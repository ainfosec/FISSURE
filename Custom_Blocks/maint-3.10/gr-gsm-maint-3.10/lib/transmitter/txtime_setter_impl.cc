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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <gnuradio/io_signature.h>
#include <gsm/endian.h>
#include <gsm/gsmtap.h>

#include "txtime_setter_impl.h"

#define UNKNOWN_FN 0xffffffff
#define MAX_EARLY_TIME_DIFF 10.0

namespace gr {
  namespace gsm {

    txtime_setter::sptr
    txtime_setter::make(
      uint32_t init_fn, uint64_t init_time_secs,
      double init_time_fracs, uint64_t time_hint_secs,
      double time_hint_fracs, double timing_advance,
      double delay_correction)
    {
      return gnuradio::get_initial_sptr
        (new txtime_setter_impl(init_fn, init_time_secs,
          init_time_fracs, time_hint_secs, time_hint_fracs,
          timing_advance, delay_correction));
    }

    /*
     * The private constructor
     */
    txtime_setter_impl::txtime_setter_impl(
      uint32_t init_fn, uint64_t init_time_secs,
      double init_time_fracs, uint64_t time_hint_secs,
      double time_hint_fracs, double timing_advance,
      double delay_correction
    ) : gr::block("txtime_setter",
          gr::io_signature::make(0, 0, 0),
          gr::io_signature::make(0, 0, 0)),
        d_time_hint(time_hint_secs,time_hint_fracs),
        d_time_ref(init_time_secs,init_time_fracs),
        d_delay_correction(delay_correction),
        d_timing_advance(timing_advance),
        d_fn_ref(init_fn),
        d_ts_ref(0)
    {
        // Register I/O ports
        message_port_register_in(pmt::mp("fn_time"));
        message_port_register_in(pmt::mp("bursts_in"));
        message_port_register_out(pmt::mp("bursts_out"));

        // Bind message handlers
        set_msg_handler(pmt::mp("fn_time"),
          boost::bind(&txtime_setter_impl::process_fn_time_reference,
            this, boost::placeholders::_1));
        set_msg_handler(pmt::mp("bursts_in"),
          boost::bind(&txtime_setter_impl::process_txtime_of_burst,
            this, boost::placeholders::_1));
    }

    /*
     * Our virtual destructor.
     */
    txtime_setter_impl::~txtime_setter_impl()
    {
    }
    
    void txtime_setter_impl::process_fn_time_reference(pmt::pmt_t msg)
    {
      pmt::pmt_t fn_time, time_hint;

      fn_time = pmt::dict_ref(msg,
        pmt::intern("fn_time"), pmt::PMT_NIL);
      time_hint = pmt::dict_ref(msg,
        pmt::intern("time_hint"), pmt::PMT_NIL);

      if (fn_time != pmt::PMT_NIL) {
        uint32_t fn_ref = static_cast<uint32_t>
          (pmt::to_uint64(pmt::car(pmt::car(fn_time))));
        uint32_t ts = static_cast<uint32_t>
          (pmt::to_uint64(pmt::cdr(pmt::car(fn_time))));
        uint64_t time_secs = pmt::to_uint64(
          pmt::car(pmt::cdr(fn_time)));
        double time_fracs = pmt::to_double(
          pmt::cdr(pmt::cdr(fn_time)));

        set_fn_time_reference(fn_ref, ts, time_secs, time_fracs);
      } else if (time_hint != pmt::PMT_NIL) {
        set_time_hint(pmt::to_uint64(pmt::car(fn_time)),
          pmt::to_double(pmt::cdr(fn_time)));
      }
    }

    void txtime_setter_impl::process_txtime_of_burst(pmt::pmt_t msg_in)
    {
      pmt::pmt_t blob = pmt::cdr(msg_in);

      // Extract GSMTAP header from message
      gsmtap_hdr *header = (gsmtap_hdr *) pmt::blob_data(blob);
      uint32_t frame_nr = be32toh(header->frame_number);
      uint32_t ts_num = header->timeslot;

      if (d_fn_ref == UNKNOWN_FN) {
        std::cout << "Missing reference TDMA frame number, dropping "
                  << "burst (fn=" << frame_nr << ", tn=" << ts_num << ")"
                  << std::endl;
        return;
      }

      time_format txtime = fn_time_delta_cpp(d_fn_ref, d_time_ref,
        frame_nr, d_time_hint, ts_num, d_ts_ref);

      time_spec_t txtime_spec = time_spec_t(txtime.first, txtime.second);
      txtime_spec -= d_delay_correction;
      txtime_spec -= d_timing_advance;

      time_spec_t current_time_estimate = time_spec_t(d_time_hint.first, d_time_hint.second);

      if (txtime_spec <= current_time_estimate) { // Drop too late bursts
        std::cout << "lB" << std::flush;
      } else if (txtime_spec > current_time_estimate + MAX_EARLY_TIME_DIFF) { // Drop too early bursts
        std::cout << "eB" << std::flush;      //TODO: too early condition might happen when changing BTSes.
                                              //Wrong fn_time is applied to new or old bursts in such situation.
                                              //This solution is not perfect as MS might be blocked upto
                                              //MAX_EARLY_TIME_DIFF seconds.
                                              //Better solution would be to indentify fn_time and burst coming
                                              //from given BTS (i.e. based on ARFCN) and dropping bursts for which
                                              //the bts_id doesn't match with bts_id of fn_time.
      } else { //process bursts that are in the right time-frame
        pmt::pmt_t tags_dict = pmt::dict_add(
          pmt::make_dict(),
          pmt::intern("tx_time"),
          pmt::make_tuple(
            pmt::from_uint64(txtime_spec.get_full_secs()),
            pmt::from_double(txtime_spec.get_frac_secs()))
        );

        tags_dict = pmt::dict_add(tags_dict,
          pmt::intern("fn"), pmt::from_uint64(frame_nr));
        tags_dict = pmt::dict_add(tags_dict,
          pmt::intern("ts"), pmt::from_uint64(ts_num));

        // Send a message to the output
        pmt::pmt_t msg_out = pmt::cons(tags_dict, pmt::cdr(msg_in));
        message_port_pub(pmt::mp("bursts_out"), msg_out);
      }
    }

    void txtime_setter_impl::set_fn_time_reference(
      uint32_t fn, uint32_t ts, uint64_t time_secs,
      double time_fracs)
    {
      d_fn_ref = fn;
      d_ts_ref = ts;
      d_time_ref = std::make_pair(time_secs, time_fracs);
      set_time_hint(time_secs, time_fracs);
    }

    void txtime_setter_impl::set_time_hint(
      uint64_t time_hint_secs, double time_hint_fracs)
    {
      d_time_hint = std::make_pair(time_hint_secs, time_hint_fracs);
    }

    void txtime_setter_impl::set_delay_correction(double delay_correction)
    {
      d_delay_correction = delay_correction;
    }

    void txtime_setter_impl::set_timing_advance(double timing_advance)
    {
      d_timing_advance = timing_advance;
    }

  } /* namespace gsm */
} /* namespace gr */
