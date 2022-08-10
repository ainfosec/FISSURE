/* -*- c++ -*- */
/*
 * Copyright 2020 Lime Microsystems <info@limemicro.com>
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

#ifndef INCLUDED_LIMERFE_H
#define INCLUDED_LIMERFE_H

#include <limeRFE.h>
#include <limesdr/api.h>
#include <iostream>
#include <string>

namespace gr {
namespace limesdr {

/*!
 * \brief GNURadio block to control LimeRFE boards
 * \ingroup limesdr
 *
 */
class LIMESDR_API rfe
{
public:
    rfe(int comm_type,
        std::string device,
        std::string config_file,
        char IDRX,
        char IDTX,
        char PortRX,
        char PortTX,
        char Mode,
        char Notch,
        char Atten);
    ~rfe();
    /**
     * Change LimeRFE Mode
     *
     * @param   mode  Mode to be set: RX(0), TX(1), NONE(2), TXRX(3)
     *
     * @return 0 on success, other on failure (see LimeRFE error codes)
     */
    int change_mode(int mode);
    /**
     * Enable or disbale fan
     *
     * @param   enable  fan state: 0 - disable; 1 - enable.
     *
     * @return 0 on success, other on failure (see LimeRFE error codes)
     */
    int set_fan(int enable);
    /**
     * Set RX Attenuation value
     *
     * @param   attenuation  Specifies the attenuation in the RX path. Attenuation [dB] =
     * 2 * attenuation. Value range: [0,7]
     *
     * @return 0 on success, other on failure (see LimeRFE error codes)
     */
    int set_attenuation(int attenuation);
    /**
     * Enable or disable AM/FM notch filter
     *
     * @param   enable notch state: 0 - disable; 1 - enable
     *
     * @note Notch filter is only possible up to HAM 430-440 MHz, or Wideband 1-1000 MHz
     * @return 0 on success, other on failure (see LimeRFE error codes)
     */
    int set_notch(int enable);

private:
    rfe_dev_t* rfe_dev = nullptr;
    rfe_boardState boardState = { RFE_CID_WB_1000,
                                  RFE_CID_WB_1000,
                                  RFE_PORT_1,
                                  RFE_PORT_1,
                                  RFE_MODE_NONE,
                                  RFE_NOTCH_OFF,
                                  0,
                                  0,
                                  0 };
    int sdr_device_num = 0;

    void print_error(int error);

    void get_board_state()
    {
        rfe_boardState currentState = { 0 };
        if (RFE_GetState(rfe_dev, &currentState) != 0) {
            std::cout << "LimeRFE: failed to get board state" << std::endl;
            return;
        }

        std::cout << "LimeRFE: RX channel: " << (int)currentState.channelIDRX << std::endl;
        std::cout << "LimeRFE: TX channel: " << (int)currentState.channelIDTX << std::endl;
        std::cout << "LimeRFE: PortRX: " << (int)currentState.selPortRX << std::endl;
        std::cout << "LimeRFE: PortTx: " << (int)currentState.selPortTX << std::endl;
        std::cout << "LimeRFE: Mode: " << (int)currentState.mode << std::endl;
        std::cout << "LimeRFE: Notch: " << (int)currentState.notchOnOff << std::endl;
        std::cout << "LimeRFE: Attenuation: " << (int)currentState.attValue << std::endl;
        std::cout << "LimeRFE: Enable SWR: " << (int)currentState.enableSWR << std::endl;
        std::cout << "LimeRFE: SourceSWR: " << (int)currentState.sourceSWR << std::endl;
    }
};

} // namespace limesdr
} // namespace gr

#endif /* INCLUDED_LIMERFE_H */
