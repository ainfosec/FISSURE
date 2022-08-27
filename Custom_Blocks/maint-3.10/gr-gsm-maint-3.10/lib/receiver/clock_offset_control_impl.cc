/* -*- c++ -*- */
/*
 * @file
 * @author (C) 2015-2017 Piotr Krysik <ptrkrysik@gmail.com>
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sch.h>
#include <gsm/gsm_constants.h>
#include "clock_offset_control_impl.h"

namespace gr
{
namespace gsm
{
clock_offset_control::sptr
clock_offset_control::make(float fc, float samp_rate, unsigned int osr)
{
    return gnuradio::get_initial_sptr
           (new clock_offset_control_impl(fc, samp_rate, osr));
}


/*
 * The private constructor
 */
clock_offset_control_impl::clock_offset_control_impl(float fc, float samp_rate, unsigned int osr)
    : gr::block("clock_offset_control",
                gr::io_signature::make(0, 0, 0),
                gr::io_signature::make(0, 0, 0))

{
    message_port_register_in(pmt::mp("measurements"));
    set_msg_handler(pmt::mp("measurements"), boost::bind(&clock_offset_control_impl::process_measurement, this, boost::placeholders::_1));
    message_port_register_out(pmt::mp("ctrl"));
    
    set_fc(fc);
    set_samp_rate(samp_rate);
    set_osr(osr);
    d_alfa = 0.3;
    d_ppm_estimate = -1e6;
    d_last_ppm_estimate = -1e6;    
    d_first_measurement = true;
    d_counter = 0;
    d_last_state = "";
    d_current_time = 0;
    d_last_fcch_time = 0;
    d_first_time = true;
}

/*
 * Our virtual destructor.
 */
clock_offset_control_impl::~clock_offset_control_impl()
{
}

void clock_offset_control_impl::set_osr(unsigned int osr)
{
    d_osr = osr;
}

void clock_offset_control_impl::set_fc(float fc)
{
    d_fc = fc;
}

void clock_offset_control_impl::set_samp_rate(float samp_rate)
{
    d_samp_rate = samp_rate;
}

void clock_offset_control_impl::process_measurement(pmt::pmt_t msg)
{
    if(pmt::is_tuple(msg))
    {
        std::string key = pmt::symbol_to_string(pmt::tuple_ref(msg,0));
        if(key == "current_time")
        {
            d_current_time = pmt::to_double(pmt::tuple_ref(msg,1));
            if(d_first_time==true)
            {
                d_last_fcch_time = d_current_time;
                d_first_time = false;
            }
            else
            if((d_current_time - d_last_fcch_time) > 0.5 && d_last_state == "fcch_search")
            {
                timed_reset();
            }
        }
        else 
        if(key == "freq_offset")
        {
            float freq_offset = pmt::to_double(pmt::tuple_ref(msg,1));
            float ppm = -freq_offset/d_fc*1.0e6;
            std::string state = pmt::symbol_to_string(pmt::tuple_ref(msg,2));
            d_last_state = state;
            if(std::abs(ppm) < 100.0) //safeguard against flawed measurements
            {

                if(state == "fcch_search")
                {
                    send_ctrl_messages(freq_offset);
                    d_last_fcch_time = d_current_time;
                } 
                else 
                if (state == "synchronized")
                {
                    d_last_fcch_time = d_current_time;
                    if(d_first_measurement)
                    {
                        d_ppm_estimate = ppm;
                        d_first_measurement = false; 
                    }
                    else
                    {
                        d_ppm_estimate = (1-d_alfa)*d_ppm_estimate+d_alfa*ppm;
                    }
                    
                    if(d_counter == 5)
                    {
                        d_counter = 0;
                        if(std::abs(d_last_ppm_estimate-d_ppm_estimate) > 0.1)
                        {
//                            pmt::pmt_t msg_ppm = pmt::from_double(ppm);
//                            message_port_pub(pmt::intern("ppm"), msg_ppm);
                            send_ctrl_messages(freq_offset);
                            d_last_ppm_estimate = d_ppm_estimate;
                        }
                    }
                    else
                    {
                        d_counter=d_counter+1;
                    }
                }
                else
                if(state == "sync_loss")
                {
                    reset();
//                    pmt::pmt_t msg_ppm = pmt::from_double(0.0);
//                    message_port_pub(pmt::intern("ppm"), msg_ppm);
                    send_ctrl_messages(0);
                }
            }
        }
    }
}

void clock_offset_control_impl::send_ctrl_messages(float freq_offset)
{
    double samp_rate_ratio = d_samp_rate / (d_osr * GSM_SYMBOL_RATE);

    pmt::pmt_t messages = pmt::make_dict();
    messages = dict_add(messages, pmt::string_to_symbol("set_phase_inc"), pmt::from_double(-2*M_PI*freq_offset/(d_osr * GSM_SYMBOL_RATE)));
    messages = dict_add(messages, pmt::string_to_symbol("set_resamp_ratio"), pmt::from_double((1-(freq_offset/d_fc))*samp_rate_ratio));
    messages = dict_add(messages, pmt::string_to_symbol("setting_freq_offset"), pmt::from_double(-freq_offset));
    messages = dict_add(messages, pmt::string_to_symbol("clock_offset_in_ppm"), pmt::from_double(-freq_offset/d_fc*1.0e6));
    message_port_pub(pmt::intern("ctrl"), messages);
}

void clock_offset_control_impl::timed_reset()
{
    reset();
    send_ctrl_messages(0);
}

void clock_offset_control_impl::reset()
{
    d_ppm_estimate = -1e6;
    d_counter = 0;
    d_first_measurement = true;
}

} /* namespace gsm */
} /* namespace gr */

