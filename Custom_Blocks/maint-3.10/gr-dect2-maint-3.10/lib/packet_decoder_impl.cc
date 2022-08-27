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
#include "packet_decoder_impl.h"

#include <cstdio> 
#include <iomanip>

namespace gr {
  namespace dect2 {

    // scramble table with corrections by Jakub Hruska
    static const uint8_t scrt[8][31]=
    {
        {0x3B, 0xCD, 0x21, 0x5D, 0x88, 0x65, 0xBD, 0x44, 0xEF, 0x34, 0x85, 0x76, 0x21, 0x96, 0xF5, 0x13, 0xBC, 0xD2, 0x15, 0xD8, 0x86, 0x5B, 0xD4, 0x4E, 0xF3, 0x48, 0x57, 0x62, 0x19, 0x6F, 0x51},
        {0x32, 0xDE, 0xA2, 0x77, 0x9A, 0x42, 0xBB, 0x10, 0xCB, 0x7A, 0x89, 0xDE, 0x69, 0x0A, 0xEC, 0x43, 0x2D, 0xEA, 0x27, 0x79, 0xA4, 0x2B, 0xB1, 0x0C, 0xB7, 0xA8, 0x9D, 0xE6, 0x90, 0xAE, 0xC4},
        {0x2D, 0xEA, 0x27, 0x79, 0xA4, 0x2B, 0xB1, 0x0C, 0xB7, 0xA8, 0x9D, 0xE6, 0x90, 0xAE, 0xC4, 0x32, 0xDE, 0xA2, 0x77, 0x9A, 0x42, 0xBB, 0x10, 0xCB, 0x7A, 0x89, 0xDE, 0x69, 0x0A, 0xEC, 0x43},
        {0x27, 0x79, 0xA4, 0x2B, 0xB1, 0x0C, 0xB7, 0xA8, 0x9D, 0xE6, 0x90, 0xAE, 0xC4, 0x32, 0xDE, 0xA2, 0x77, 0x9A, 0x42, 0xBB, 0x10, 0xCB, 0x7A, 0x89, 0xDE, 0x69, 0x0A, 0xEC, 0x43, 0x2D, 0xEA},
        {0x19, 0x6F, 0x51, 0x3B, 0xCD, 0x21, 0x5D, 0x88, 0x65, 0xBD, 0x44, 0xEF, 0x34, 0x85, 0x76, 0x21, 0x96, 0xF5, 0x13, 0xBC, 0xD2, 0x15, 0xD8, 0x86, 0x5B, 0xD4, 0x4E, 0xF3, 0x48, 0x57, 0x62},
        {0x13, 0xBC, 0xD2, 0x15, 0xD8, 0x86, 0x5B, 0xD4, 0x4E, 0xF3, 0x48, 0x57, 0x62, 0x19, 0x6F, 0x51, 0x3B, 0xCD, 0x21, 0x5D, 0x88, 0x65, 0xBD, 0x44, 0xEF, 0x34, 0x85, 0x76, 0x21, 0x96, 0xF5},
        {0x0C, 0xB7, 0xA8, 0x9D, 0xE6, 0x90, 0xAE, 0xC4, 0x32, 0xDE, 0xA2, 0x77, 0x9A, 0x42, 0xBB, 0x10, 0xCB, 0x7A, 0x89, 0xDE, 0x69, 0x0A, 0xEC, 0x43, 0x2D, 0xEA, 0x27, 0x79, 0xA4, 0x2B, 0xB1},
        {0x79, 0xA4, 0x2B, 0xB1, 0x0C, 0xB7, 0xA8, 0x9D, 0xE6, 0x90, 0xAE, 0xC4, 0x32, 0xDE, 0xA2, 0x77, 0x9A, 0x42, 0xBB, 0x10, 0xCB, 0x7A, 0x89, 0xDE, 0x69, 0x0A, 0xEC, 0x43, 0x2D, 0xEA, 0x27}
    };

    static const uint16_t crc_table[16] = 
    {
        0x0000, 0x0589, 0x0b12, 0x0e9b, 0x1624, 0x13ad, 0x1d36, 0x18bf,
        0x2c48, 0x29c1, 0x275a, 0x22d3, 0x3a6c, 0x3fe5, 0x317e, 0x34f7
    };

    static uint16_t calc_rcrc(uint8_t *data, unsigned data_len)
    {
        uint16_t crc;
        unsigned tbl_idx;

        crc = 0x0000;
        while (data_len--) 
        {
            tbl_idx = (crc >> 12) ^ (*data >> 4);
            crc = crc_table[tbl_idx & 0x0f] ^ (crc << 4);
            tbl_idx = (crc >> 12) ^ (*data >> 0);
            crc = crc_table[tbl_idx & 0x0f] ^ (crc << 4);
            data++;
        }
        return crc ^ 0x0001;
    }



    static uint8_t calc_xcrc(uint8_t *b_field)
    {
        uint8_t rbits[10];
        uint8_t gp = 0x10;
        uint8_t crc;
        uint8_t next;
        uint32_t i, j;
        uint32_t bi;
        uint32_t bw;
        uint32_t nb;
        uint8_t  rbyte;
        uint32_t rbit_cnt, rbyte_cnt;


        // Extract test bits 
        memset(rbits, 0, sizeof(rbits));
        rbit_cnt = 0;
        rbyte_cnt = 0;
        for(i = 0; i <= (83 - 4); i++)
        {
            bi = i + 48  * (1 + (i >> 4));
            nb = bi >> 3;
            bw = b_field[nb];

            rbyte <<= 1;
            rbyte |= (bw >> (7 - (bi - (nb << 3)))) & 1;

            if(++rbit_cnt == 8)
            {
                rbits[rbyte_cnt++] = rbyte; 
                rbit_cnt = 0;                              
            }          
        }


        crc = rbits[0];
        i = 0;
        while(i < 10)
        {
            if(i < (10 - 1))
              next = rbits[i + 1];
            else
              next=0;
            i++;
            j = 0;
            while(j < 8)
            {
                while(!(crc & 0x80))
                {
                    crc <<= 1;
                    crc |= !!(next & 0x80);
                    next <<= 1;
                    j++;
                    if(j > 7)
                      break;
                }
                if(j > 7)
                  break;
                crc <<= 1;
                crc |= !!(next & 0x80);
                next <<= 1;
                j++;
                crc ^= gp;
            }
        }
        return crc >> 4;
    }


    static bool part_id_cmp(uint8_t *id1, uint8_t *id2)
    {
        for(uint32_t i = 0; i < 5; i++)
            if(id1[i] != id2[i])
                return false;              
        return true;
    }



    uint32_t packet_decoder_impl::decode_afield(uint8_t *field_data)
    {

        uint16_t rcrc = (uint16_t)field_data[6] << 8 | field_data[7];                
        uint16_t crc  = calc_rcrc(field_data, 6);
                                                        
        if(crc != rcrc)
        {
            d_cur_part->afield_bad_crc_cnt++;
            return 0;
        }

        
        uint8_t  afield_header = field_data[0]; 
        uint8_t  ta_bits = (afield_header >> 5) & 0x07;;

        switch(ta_bits)
        {
            case 0:
            break;
    
            case 1:
            break;
        
            case 3:          
                d_cur_part->part_id[0] = field_data[1];
                d_cur_part->part_id[1] = field_data[2];
                d_cur_part->part_id[2] = field_data[3];
                d_cur_part->part_id[3] = field_data[4];
                d_cur_part->part_id[4] = field_data[5];
                d_cur_part->part_id_rcvd = true;
            break;
    
            case 4:  // multiframe synchronization and system information (Qt) - translated every 16 frames in frame number 8
                //std::cout << "===== FRAME 8 =====" << std::endl;            
                d_cur_part->frame_number = 8;
                d_cur_part->qt_rcvd = true;
    
                //qt_parse(afield.tail);
            break;
    
            case 6:
                //mt_parse(afield.tail);
            break;
    
            case 7:
                //if(pt == _RFP_)     
                //pt_parse(afield.tail);
            break;    
        }
    
    
        if(((afield_header >> 1) & 7) == 0)
        {
            if(d_cur_part->voice_present == false)
            {
                d_cur_part->voice_present = true;
                d_cur_part->log_update = true;
            }
        }
        else
        {
            if(d_cur_part->voice_present == true)
            {
                d_cur_part->voice_present = false;
                d_cur_part->log_update = true;
            }
        }
            
        return 1;
    }



    packet_decoder::sptr
    packet_decoder::make()
    {
      return gnuradio::get_initial_sptr
        (new packet_decoder_impl());
    }

    
    packet_decoder_impl::packet_decoder_impl()
      : gr::tagged_stream_block("packet_decoder",
               gr::io_signature::make(1, 1, sizeof(unsigned char)),
               gr::io_signature::make(1, 1, sizeof(unsigned char)), std::string("packet_len"))
    {
        set_tag_propagation_policy(TPP_DONT);

        d_selected_rx_id = 0;

        message_port_register_in(pmt::mp("rcvr_msg_in"));
        set_msg_handler(pmt::mp("rcvr_msg_in"), boost::bind(&packet_decoder_impl::msg_event_handler, this, boost::placeholders::_1));
        message_port_register_out(pmt::mp("log_out"));   


        memset(&d_part_descriptor, 0, sizeof(d_part_descriptor));     
    }

    
    packet_decoder_impl::~packet_decoder_impl()
    {
    }

    int packet_decoder_impl::calculate_output_stream_length(const gr_vector_int &ninput_items)
    {
        int noutput_items = 80;
        return noutput_items ;
    }

    void packet_decoder_impl::msg_event_handler(pmt::pmt_t msg)
    {
        if(pmt::dict_has_key( msg, pmt::mp("rcvr_msg_id")))
        {
            pmt::pmt_t msg_id = pmt::dict_ref( msg, pmt::mp("rcvr_msg_id"), pmt::PMT_NIL); 
            if(pmt::eq(msg_id, pmt::mp("lost_part")))
            {                
                //std::cout << "*********** LOST part ************" << std::endl;

                // Remove active part
                uint32_t rx_id = (uint32_t)pmt::to_uint64(pmt::dict_ref( msg, pmt::mp("part_rx_id"), pmt::PMT_NIL));

                part_descriptor_item *part_item = &d_part_descriptor[rx_id];
                part_item->active = false;
                part_item->voice_present = false;                
                part_item->log_update = false;
                part_item->qt_rcvd = false;
                if(part_item->part_id_rcvd == true)
                    print_parts();

                // Cleare part's pair                  
                if(part_item->pair != NULL)
                {
                    if(part_item->type == _PP_)  
                    {
                        part_item->pair->pair = NULL;  
                    }
                    else if(part_item->type == _RFP_)  
                    {
                        part_item->pair->voice_present = false;
                        part_item->pair->pair = NULL;
                    }

                    part_item->pair = NULL;
                }                                          
            }
        }       
    }

    void packet_decoder_impl::print_parts(void)
    {
        std::ostringstream os;
        
        os << "===== AVAILABLE PARTS =====" << std::endl;
        for(uint32_t rx_id = 0; rx_id < MAX_PARTS; rx_id++)
        {
            if(d_part_descriptor[rx_id].active == true)
            {
                part_descriptor_item *part_item = &d_part_descriptor[rx_id];
                if(d_selected_rx_id == rx_id)
                    os << "* ";
                else
                    os << "  ";
                  
                os << rx_id << "   " << std::hex << std::setfill('0') << std::setw(2) << (uint32_t)part_item->part_id[0] << \
                                                    std::setfill('0') << std::setw(2) << (uint32_t)part_item->part_id[1] << \
                                                    std::setfill('0') << std::setw(2) << (uint32_t)part_item->part_id[2] << \
                                                    std::setfill('0') << std::setw(2) << (uint32_t)part_item->part_id[3] << \
                                                    std::setfill('0') << std::setw(2) << (uint32_t)part_item->part_id[4];

                if(part_item->type == _RFP_)
                    os << " RFP ";
                else
                    os << " PP  ";

                if(part_item->voice_present)
                    os << "  " << "V" << std::endl;
                else
                    os << "  " << std::endl;

            }

        }
        os << "===========================\n\n";

        //std::cout << os.str() << std::endl;

        pmt::pmt_t msg = pmt::make_dict();
        msg = pmt::dict_add(msg, pmt::mp("log_msg"), pmt::mp(os.str()));
        message_port_pub(pmt::mp("log_out"), msg);    
    }

    void packet_decoder_impl::select_rx_part(uint32_t rx_id)
    {
        d_selected_rx_id = rx_id;
    }

    int packet_decoder_impl::work (int noutput_items,
                       gr_vector_int &ninput_items,
                       gr_vector_const_void_star &input_items,
                       gr_vector_void_star &output_items)
    {
        const uint8_t *in = (const uint8_t *) input_items[0];
        uint8_t *out = (uint8_t *) output_items[0];
        uint32_t packet_length = ninput_items[0];

        uint32_t rx_id;
        uint64_t rx_seq;
        part_type ptype = _RFP_;


        std::vector<tag_t> tags;
        get_tags_in_range(tags, 0, nitems_read(0), nitems_read(0) + packet_length);

        for (size_t i = 0; i < tags.size(); i++) 
        {
            if(pmt::eq(tags[i].key, pmt::mp("part_rx_id")))
            {
                rx_id = (uint32_t)pmt::to_uint64(tags[i].value); 
            }
            else if(pmt::eq(tags[i].key, pmt::mp("rx_seq")))
            {
                rx_seq = (uint64_t)pmt::to_uint64(tags[i].value); 
            }            
            else if(pmt::eq(tags[i].key, pmt::mp("part_type")))
            {
                if(pmt::eq(tags[i].value, pmt::mp("RFP")))
                    ptype = _RFP_;
                else
                    ptype = _PP_;                
            }          
        } 

        d_cur_part = &d_part_descriptor[rx_id];

        if(d_cur_part->active == true)
        {
            uint64_t seq_diff = (rx_seq - d_cur_part->rx_seq) & 0x1F;
                      
            if(ptype == _RFP_)
            {
                d_cur_part->frame_number = (d_cur_part->frame_number + seq_diff) & 0xF;

                // Update frame number for pair if available              
                if(d_cur_part->pair != NULL)
                {
                    d_cur_part->pair->frame_number = d_cur_part->frame_number; 
                    d_cur_part->pair->rpf_fn_cor = true;
                }              
            }
            else if(ptype == _PP_)
            {
                if(d_cur_part->rpf_fn_cor == true)
                    d_cur_part->rpf_fn_cor ==  false;
                else
                    d_cur_part->frame_number = (d_cur_part->frame_number + seq_diff) & 0xF; 
            }

            d_cur_part->rx_seq = rx_seq; 
            d_cur_part->packet_cnt++;   
        }
        else
        {
            // Register a new part
            d_cur_part->active = true; 
            d_cur_part->frame_number = 0;
            d_cur_part->rx_seq = rx_seq;
            d_cur_part->voice_present = false;
            d_cur_part->packet_cnt = 0;
            d_cur_part->afield_bad_crc_cnt = 0;
            d_cur_part->log_update = true;
            d_cur_part->part_id_rcvd =  false;
            d_cur_part->qt_rcvd = false;
            d_cur_part->type = ptype;
            d_cur_part->pair = NULL;
            //std::cout << "*********** NEW part ************" << std::endl;
        }

        // Try to find pair RFP for PP       
        if(d_cur_part->pair == NULL && d_cur_part->type == _PP_ && d_cur_part->part_id_rcvd == true)
        {
            for(uint32_t i = 0; i < MAX_PARTS; i++)
            {
                if(i != rx_id)
                {
                    if(d_part_descriptor[i].active == true)
                    {
                        if(part_id_cmp(d_cur_part->part_id, d_part_descriptor[i].part_id) == true)
                        {
                            d_cur_part->pair = &d_part_descriptor[i];
                            d_part_descriptor[i].pair = d_cur_part;
                        }
                    }
                }
            }
        }

        uint8_t tmp_byte;
        uint32_t a_field_byte_cnt = 0;
        uint8_t a_field[8];

        // Extract A-field
        for(uint32_t i = 0; i < A_FIELD_BITS; i++)
        {
            if(i && ((i & 0x7) == 0))
                a_field[a_field_byte_cnt++] = tmp_byte;   
            tmp_byte = (tmp_byte << 1) | (*in++ & 0x1);
        }
        a_field[a_field_byte_cnt] = tmp_byte;   

        
        decode_afield(a_field);


        if(ptype == _RFP_ && d_cur_part->qt_rcvd && d_cur_part->pair != NULL)
            d_cur_part->pair->qt_rcvd = true;

      
        if(d_cur_part->log_update && d_cur_part->part_id_rcvd)
        {
            print_parts();
            d_cur_part->log_update = false;
        }
        

        if(rx_id == d_selected_rx_id)
        {
            if(d_cur_part->active && d_cur_part->voice_present && d_cur_part->qt_rcvd)
            {              
                uint8_t b_field[40];
                uint8_t tmp_byte;
                uint32_t b_field_byte_cnt = 0;
                
            
                for(uint32_t i = 0; i < B_FIELD_BITS; i++)
                {
                    if(i && ((i & 0x7) == 0))
                      b_field[b_field_byte_cnt++] = tmp_byte;   
                    tmp_byte = (tmp_byte << 1) | (*in++ & 0x1);
                }

                b_field[b_field_byte_cnt] = tmp_byte;   


                uint8_t xcrc = calc_xcrc(b_field);

                uint8_t x_field = 0;
                x_field |= ((*in++ & 0x1) << 3);
                x_field |= ((*in++ & 0x1) << 2);
                x_field |= ((*in++ & 0x1) << 1);
                x_field |= (*in & 0x1); 

                if(xcrc == x_field)
                {                               
                    uint8_t *ptr = b_field;                       
                    uint32_t whitener_offset = d_cur_part->frame_number % 8;         
                    uint8_t descrt_byte;

                    for(uint32_t i = 0; i < 40; i++)
                    {
                        descrt_byte = *ptr++ ^ scrt[whitener_offset][i % 31];
                        *out++ = (descrt_byte >> 4) & 0xF;
                        *out++ =  descrt_byte & 0xF;
                    }
        
                    noutput_items = 80;
                }
                else
                {
                    for(uint32_t i = 0; i < 80; i++)
                        *out++ = 0;
                    noutput_items = 80; 
                }
            }
            else
            {
                for(uint32_t i = 0; i < 80; i++)
                  *out++ = 0;
                noutput_items = 80;
            }

        } 
        else      
            noutput_items = 0;   
      
        return noutput_items;
    }

  } /* namespace dect2 */
} /* namespace gr */

