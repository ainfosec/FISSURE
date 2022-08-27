/* -*- c++ -*- */
/* 
 * Copyright 2015 Pavel Yazev <pyazev@gmail.com>
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
#include "packet_receiver_impl.h"

namespace gr {
  namespace dect2 {

    packet_receiver::sptr
    packet_receiver::make()
    {
      return gnuradio::get_initial_sptr
        (new packet_receiver_impl());
    }

    packet_receiver_impl::packet_receiver_impl()
      : gr::block("packet_receiver",
                 gr::io_signature::make(1, 1, sizeof(float)),
                 gr::io_signature::make(1, 1, sizeof(unsigned char)))        
    {
        set_fixed_rate(true);
        set_history(4);
        set_decimation(4);

        message_port_register_out(pmt::mp("rcvr_msg_out"));        


        d_rx_bits_buf_index = 0;
        d_smpl_buf_index    = 0;
        d_sync_state        = _WAIT_BEGIN_;

        d_inc_smpl_cnt = 0;

        d_part_activity = 0;
    }



    packet_receiver_impl::~packet_receiver_impl()
    {
    }

    void packet_receiver_impl::forecast (int noutput_items, gr_vector_int &ninput_items_required)
    {
        unsigned ninputs = ninput_items_required.size ();
        for (unsigned i = 0; i < ninputs; i++)
            ninput_items_required[i] = fixed_rate_noutput_to_ninput(noutput_items);
    }


    int packet_receiver_impl::fixed_rate_noutput_to_ninput(int noutput_items)
    {
        return noutput_items * decimation() + history() - 1;
    }

    int packet_receiver_impl::fixed_rate_ninput_to_noutput(int ninput_items)
    {
        return std::max(0, ninput_items - (int)history() + 1) / decimation();
    }


    //   
    // Check for parts activity
    //       Return: 
    //               Part RX ID - if there is no activity for a part
    //                  -1      - otherwise
    //
    int packet_receiver_impl::check_part_activity(void)
    {          
        if(d_part_activity)
        {
            uint32_t j = 0;
            uint32_t part_mask = 1;
            while(part_mask <= d_part_activity)      
            {
                if(d_part_activity & part_mask)
                {
                    if(d_inc_smpl_cnt - d_part_time[j] > (4 * INTER_FRAME_TIME))
                    {
                        // Release part
                        d_part_activity &= ~part_mask;
                        return j;
                    }
                }
                part_mask <<= 1;
                j++;
            } 
        }        
        return -1;
    }

    //
    //  If there are several DECT parts on air we need to keep track each in correct way.
    //  This function does this by taking into account time intervals (based on incomming sample counter)
    //  between received bursts.
    //  Return:
    //          Part RX ID - if apropriate part is found or a new one assigned
    //                  -1 - otherwise 
    //
    int packet_receiver_impl::register_part(void)
    {
        
        if(d_part_activity)       
        {
            uint32_t j = 0;
            uint32_t part_mask = 1;
            uint32_t seq;

            while(j < MAX_PARTS)
            {
                if(d_part_activity & part_mask)
                {
                    uint64_t ltmp = (d_inc_smpl_cnt - d_part_time[j]) % INTER_FRAME_TIME;
                    if(ltmp < TIME_TOL)
                    {
                        seq = (d_inc_smpl_cnt - d_part_time[j])/INTER_FRAME_TIME;
                        break;
                    }
                    else if(INTER_FRAME_TIME - ltmp <= TIME_TOL)
                    {
                        seq = 1 + (d_inc_smpl_cnt - d_part_time[j])/INTER_FRAME_TIME;       
                        break;            
                    }  
                }

                part_mask <<= 1;
                j++;
            }
          
            if(j < MAX_PARTS)
            {
                d_part_time[j] = d_inc_smpl_cnt;
                d_part_seq[j]  = (d_part_seq[j] + seq) & 0x1F;
                return j;
            }
            else
            {
                // Adding a new active part                   
                j = 0;
                part_mask = 1;
                while(j < MAX_PARTS)
                    if(d_part_activity & part_mask)
                    {
                        part_mask <<= 1;
                        j++;
                    }
                    else
                    {
                        d_part_activity |= part_mask;
                        break;
                    } 
        
                if(j < MAX_PARTS)
                {                           
                    d_part_time[j] = d_inc_smpl_cnt;        
                    d_part_seq[j]  = 0;                
                    return j;
                }
                else
                    return -1;   
            }           
        }
        else
        {
            // Adding the first active part
            d_part_time[0]  = d_inc_smpl_cnt;
            d_part_seq[0]   = 0;
            d_part_activity = 1;
            return 0;
        }               
    }


    int packet_receiver_impl::find_best_smpl_point(void)
    {
              
        if(d_begin_pos != d_end_pos)   // If (d_begin_pos == d_end_pos) we have the only optimal sample point
        {
            float max_val   = 0.0;    
            uint32_t max_index = d_begin_pos;
            while(1)
            {
                uint32_t index = d_begin_pos;                
                    
                float acc = 0.0;    
                for(uint32_t j = 0; j < 32; j++)
                {
                    acc += fabs(d_smpl_buf[index]);         
                    index = (index - 4) & (SMPL_BUF_LEN - 1);               
                }
          
                if(acc > max_val)
                {
                    max_val   = acc;
                    max_index = d_begin_pos;
                }
                        
                if(d_begin_pos == d_end_pos)
                    break;    
        
                d_begin_pos = (d_begin_pos + 1) & (SMPL_BUF_LEN - 1);         
            } 
            
            return (d_end_pos - max_index) & (SMPL_BUF_LEN - 1);
        } 

        return 0; // No Correction
    }




    int packet_receiver_impl::general_work (int noutput_items,
                       gr_vector_int &ninput_items,
                       gr_vector_const_void_star &input_items,
                       gr_vector_void_star &output_items)
    {
        const float *in = (const float *) input_items[0];
        unsigned char *out = (unsigned char *) output_items[0];

        unsigned ni = ninput_items[0] - history();
        
        uint32_t sync_detected;

        uint32_t ii = 0;
        uint32_t oo = 0;

        while(ii < ni && oo < noutput_items)
        {   

            // Detect RX bit
            uint32_t rx_bit = (*in >= 0)? 0:1;        
            d_rx_bits_buf[d_rx_bits_buf_index] = (d_rx_bits_buf[d_rx_bits_buf_index] << 1) | rx_bit;
            d_smpl_buf[d_smpl_buf_index] = *in++;                      // save samples in cyrcular buffer to search the best sample point later

            

            switch(d_sync_state)
            {
                case _WAIT_BEGIN_:
                    // Perform SYNC detect.   
                    // Because we have four samples per symbol there may be several positions where SYNC can be detected. 
                    // So we check interval and then look for the best sample point.
                    //              
                    sync_detected = ((d_rx_bits_buf[d_rx_bits_buf_index] ^ (uint32_t)RFP_SYNC_FIELD) == 0);
                
                    if(sync_detected)
                    {
                        d_part_type = _RFP_;
                    }            
                    else
                    {
                        sync_detected = ((d_rx_bits_buf[d_rx_bits_buf_index] ^ (~(uint32_t)RFP_SYNC_FIELD)) == 0);
                        if(sync_detected)
                          d_part_type = _PP_;
                    }            


                    if(sync_detected)
                    {
                        d_begin_pos  = d_smpl_buf_index;
                        d_sync_state = _WAIT_END_;      
                    }    
                break;
          
          
                case _WAIT_END_:
                    if(d_part_type == _RFP_)
                        sync_detected = ((d_rx_bits_buf[d_rx_bits_buf_index] ^ (uint32_t)RFP_SYNC_FIELD) == 0);
                    else if(d_part_type == _PP_)
                        sync_detected = ((d_rx_bits_buf[d_rx_bits_buf_index] ^ (~(uint32_t)RFP_SYNC_FIELD)) == 0);

                    if(!sync_detected)
                    {
                        d_end_pos  = (d_smpl_buf_index - 1) & (SMPL_BUF_LEN - 1);
                                              
                        // Perform correction to the best sample position                 
                        d_smpl_cnt = (1 + find_best_smpl_point()) & 3; 

                                                
                        d_cur_part_rx_id = register_part();
                        if(d_cur_part_rx_id < 0)
                        {
                            d_sync_state = _WAIT_BEGIN_;
                            break;
                        }
              
                        d_out_bit_cnt = 0;                        
                        d_sync_state    = _POST_WAIT_;                              
                    }         
                break;    
            
                case _POST_WAIT_:
                    // Receive packet payload
                    if(d_smpl_cnt == 0)
                    {
                        *out++ = (char)rx_bit;
                
                        if(d_out_bit_cnt == 0)
                        {                
                            add_item_tag(0,                  
                                nitems_written(0) + oo,      
                                pmt::mp("packet_len"),       
                                pmt::mp(P32_D_FIELD_BITS));  

                            add_item_tag(0,                  
                                nitems_written(0) + oo,      
                                pmt::mp("part_rx_id"),          
                                pmt::mp((uint64_t)d_cur_part_rx_id));     

                            add_item_tag(0,                  
                                nitems_written(0) + oo,      
                                pmt::mp("rx_seq"),          
                                pmt::mp((uint64_t)d_part_seq[d_cur_part_rx_id]));     

                            add_item_tag(0,                  
                                nitems_written(0) + oo,      
                                pmt::mp("part_type"),          
                                pmt::mp((d_part_type == _RFP_)?"RFP":"PP"));                             
                        }
                        
                        oo++;

                        if(++d_out_bit_cnt == P32_D_FIELD_BITS)
                            d_sync_state = _WAIT_BEGIN_;
                    }                                            
                break;        
            }  

            


            // Check parts activity and inform packet decoder if a part becomes inactive                       
            int32_t lost_id = check_part_activity();
            if(lost_id >= 0)
            {
                pmt::pmt_t msg = pmt::make_dict();
                msg = pmt::dict_add(msg, pmt::mp("rcvr_msg_id"), pmt::mp("lost_part"));
                msg = pmt::dict_add(msg, pmt::mp("part_rx_id"), pmt::mp((uint64_t)lost_id));
                message_port_pub(pmt::mp("rcvr_msg_out"), msg);    
            }            

                      
            d_smpl_buf_index = (d_smpl_buf_index + 1 ) & (SMPL_BUF_LEN - 1);        
            d_rx_bits_buf_index = (d_rx_bits_buf_index + 1) & 3;

            d_smpl_cnt = (d_smpl_cnt + 1) & 3;  

            d_inc_smpl_cnt++;   // Increase incomming samples counter
         
            ii++;
        }
        
        consume_each(ii); 
        return oo;
    }

  } /* namespace dect2 */
} /* namespace gr */

