/* -*- c++ -*- */
/*
 * Copyright 2022 gr-ainfosec author.
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <gnuradio/io_signature.h>
#include <sstream>
#include <time.h>
#include <zmq.hpp>

#include "wideband_detector1_impl.h"

#define DOZMQ 1

namespace gr {
  namespace ainfosec {

    wideband_detector1::sptr
    wideband_detector1::make(std::string address,float rx_freq, int fft_size, float sample_rate)
    {
      return gnuradio::get_initial_sptr
        (new wideband_detector1_impl(address, rx_freq, fft_size, sample_rate));
    }


    /*
     * The private constructor
     */
    wideband_detector1_impl::wideband_detector1_impl(std::string address,float rx_freq, int fft_size, float sample_rate)
      : gr::sync_block("wideband_detector1",
              gr::io_signature::make(1, 1, sizeof(float)),
              gr::io_signature::make(0, 0, 0)),
      my_address(address),
      my_rx_freq(rx_freq),
      my_fft_size(fft_size),
      my_sample_rate(sample_rate)
    {
        #if DOZMQ
            int major, minor, patch;
            zmq::version (&major, &minor, &patch);

            std::cout << "zmq version: " << major << "." << minor << "." << patch << std::endl;
            //if (major < 3) 
            //{
              //d_timeout = timeout*1000;
            //}
            d_context = new zmq::context_t(1);
            d_socket = new zmq::socket_t(*d_context, ZMQ_PUB);
            int time = 0;
            d_socket->setsockopt(ZMQ_LINGER, &time, sizeof(time));
            char addrcstr[64];
            strcpy(addrcstr, my_address.c_str());
            std::cout << "ready to bind: " << addrcstr << std::endl;
            d_socket->bind(addrcstr);
            counter = 0;
            timer_value = clock();
            max_power = 0;
            max_power_freq = 0;
            max_power_bin = 0;
            get_timestamp = std::time(0);
        #endif          
    }


    /*
     * Our virtual destructor.
     */
    wideband_detector1_impl::~wideband_detector1_impl()
    {
        #if DOZMQ
              d_socket->close();
              delete d_socket;
              delete d_context;
        #endif            
    }

    int
    wideband_detector1_impl::work(int noutput_items,
        gr_vector_const_void_star &input_items,
        gr_vector_void_star &output_items)
    {
        const float *in = (const float *) input_items[0];
        
        #if DOZMQ
            if (noutput_items >= 0)
            {
                if (noutput_items <= my_fft_size)
                {
                    // Get Values at Maximum Power
                    float get_power = 0;
                    float get_bin = 0;
                    for(int i=0;i<noutput_items;i++)
                    {
                        if(float(in[i]) > get_power)
                        {
                            get_power = float(in[i]);
                            get_bin = float(i);
                        }
                    }
                    if (get_power > 0)
                    {
                        // Store Most Powerful Value
                        if (get_power > max_power)
                        {
                            max_power = get_power;
                            max_power_bin = get_bin;
                            get_timestamp = std::time(0);
                        }
                        
                        // Report Every Second to Avoid Flooding ZMQ
                        if(clock() > timer_value)
                        {           
                            //counter++;
                                                               
                            // Bin:Frequency Conversion
                            max_power_freq = float(my_sample_rate)/my_fft_size*(max_power_bin-(my_fft_size/2)) + my_rx_freq;
                            
                            // Float to String
                            std::stringstream get_freq_str;
                            std::stringstream get_power_str;
                            std::stringstream get_timestamp_str;
                            get_freq_str << std::fixed << std::setprecision(0) << max_power_freq;
                            get_power_str << std::fixed << std::setprecision(0) << max_power;
                            get_timestamp_str << std::fixed << std::setprecision(2) << get_timestamp;
                                                    
                            // Send to Console, ZMQ                                      
                            //std::cout << counter << std::endl;
                            //std::cout << noutput_items << std::endl;
                            //std::cout << "The biggest number is: " << get_power << " at: " << get_freq << std::endl;                            
                            //std::string text = "TSI:/Signal Found/2260000000/-55/1526333364.11";
                                                       
                            std::string zmq_text = "TSI:/Signal Found/" + get_freq_str.str() + "/" + get_power_str.str() + "/" + get_timestamp_str.str();
                            //std::cout << zmq_text << std::endl;        
                            send(*d_socket, zmq_text);
                            
                            // Clear the Max-Power Placeholders
                            max_power = 0;
                            max_power_freq = 0;
                            max_power_bin = 0;
                            
                            // Update Timer
                            timer_value = clock();
                            timer_value += 1000000;
                            
                        }
                    }
                }
            }
        #endif
  
        // Tell runtime system how many output items we produced.
        return noutput_items;
    }
    
    bool wideband_detector1_impl::send(zmq::socket_t& socket, const std::string& string) 
    {
        std::cout << string << std::endl;
        zmq::message_t message (string.size());
        std::memcpy (message.data(), string.data(), string.size());
        auto rc = socket.send(message, zmq::send_flags::none);
        return (true);        
    }
    
    void wideband_detector1_impl::set_address(std::string address)
    {
        wideband_detector1_impl::my_address = address;
    }
    
    void wideband_detector1_impl::set_rx_freq(float rx_freq)
    {
        wideband_detector1_impl::my_rx_freq = rx_freq;
    }
    
    void wideband_detector1_impl::set_fft_size(int fft_size)
    {
        wideband_detector1_impl::my_fft_size = fft_size;
    }
     
    void wideband_detector1_impl::set_sample_rate(float sample_rate)
    {
        wideband_detector1_impl::my_sample_rate = sample_rate;
    }    
    

  } /* namespace ainfosec */
} /* namespace gr */

