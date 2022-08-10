/* -*- c++ -*- */
/*
 * Copyright 2020 Lime Microsystems.
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

#include "device_handler.h"
#include <limesdr/rfe.h>

namespace gr {
namespace limesdr {
rfe::rfe(int comm_type,
         std::string device,
         std::string config_file,
         char IDRX,
         char IDTX,
         char PortRX,
         char PortTX,
         char Mode,
         char Notch,
         char Atten)
{
    std::cout << "---------------------------------------------------------------"
              << std::endl;
    std::cout << "LimeSuite RFE info" << std::endl;
    std::cout << std::endl;

    boardState.channelIDRX = IDRX;
    boardState.channelIDTX = IDTX;
    boardState.selPortRX = PortRX;
    boardState.selPortTX = PortTX;
    boardState.mode = Mode;
    boardState.notchOnOff = Notch;
    boardState.attValue = Atten;

    if (comm_type) // SDR GPIO communication
    {
        sdr_device_num = device_handler::getInstance().open_device(device);

        std::cout << "LimeRFE: Opening through GPIO communication" << std::endl;
        rfe_dev =
            RFE_Open(nullptr, device_handler::getInstance().get_device(sdr_device_num));
        if (!rfe_dev) {
            std::cout << "LimeRFE: Failed to open device, exiting" << std::endl;
            exit(0);
        }

        // No need to set up this if it isn't automatic
        if (boardState.channelIDRX == RFE_CID_AUTO ||
            boardState.channelIDTX == RFE_CID_AUTO) {
            device_handler::getInstance().set_rfe_device(rfe_dev);

            // Update the channels since the SDR could already be set up and working
            device_handler::getInstance().update_rfe_channels();
        }
    } else // Direct USB
    {
        // Not using device handler so print the version
        std::cout << "##################" << std::endl;
        std::cout << "LimeSuite version: " << LMS_GetLibraryVersion() << std::endl;
        std::cout << "gr-limesdr version: " << GR_LIMESDR_VER << std::endl;
        std::cout << "##################" << std::endl;

        std::cout << "LimeRFE: Opening " << device << std::endl;
        rfe_dev = RFE_Open(device.c_str(), nullptr);
        if (!rfe_dev) {
            std::cout << "LimeRFE: Failed to open device, exiting" << std::endl;
            exit(0);
        }
    }

    int error = 0;
    unsigned char info[4] = { 0 };
    if ((error = RFE_GetInfo(rfe_dev, info)) != 0) {
        std::cout << "LimeRFE: Failed to get device info: ";
        print_error(error);
        exit(0);
    }
    std::cout << "LimeRFE: FW: " << (int)info[0] << " HW: " << (int)info[1] << std::endl;

    if (config_file.empty()) {
        if ((error = RFE_ConfigureState(rfe_dev, boardState)) != 0) {
            std::cout << "LimeRFE: Failed to configure device: ";
            print_error(error);
            exit(0);
        }
    } else {
        std::cout << "LimeRFE: Loading configuration file" << std::endl;
        if ((error = RFE_LoadConfig(rfe_dev, config_file.c_str())) != 0) {
            std::cout << "LimeRFE: Failed to load configuration file: ";
            print_error(error);
            exit(0);
        }
    }
    std::cout << "LimeRFE: Board state: " << std::endl;
    get_board_state();
    std::cout << "---------------------------------------------------------------"
              << std::endl;
}

rfe::~rfe()
{
    std::cout << "LimeRFE: closing" << std::endl;
    if (rfe_dev) {
        RFE_Reset(rfe_dev);
        RFE_Close(rfe_dev);
    }
}

int rfe::change_mode(int mode)
{
    if (rfe_dev) {
        if (mode == RFE_MODE_TXRX) {
            if (boardState.selPortRX == boardState.selPortTX &&
                boardState.channelIDRX < RFE_CID_CELL_BAND01) {
                std::cout
                    << "LimeRFE: mode cannot be set to RX+TX when same port is selected"
                    << std::endl;
                return -1;
            }
        }
        int error = 0;
        if (mode > 3 || mode < 0)
            std::cout << "LimeRFE: invalid mode" << std::endl;
        std::string mode_str[4] = { "RX", "TX", "NONE", "RX+TX" };
        std::cout << "LimeRFE: changing mode to " << mode_str[mode] << std::endl;
        if ((error = RFE_Mode(rfe_dev, mode)) != 0) {
            std::cout << "LimeRFE: failed to change mode:";
            print_error(error);
        }
        boardState.mode = mode;
        return error;
    }
    std::cout << "LimeRFE: no RFE device opened" << std::endl;
    return -1;
}

int rfe::set_fan(int enable)
{
    if (rfe_dev) {
        std::string enable_str[2] = { "disabling", "enabling" };
        std::cout << "LimeRFE: " << enable_str[enable] << " fan" << std::endl;
        int error = 0;
        if ((error = RFE_Fan(rfe_dev, enable)) != 0) {
            std::cout << "LimeRFE: failed to change mode:";
            print_error(error);
        }
        return error;
    }
    std::cout << "LimeRFE: no RFE device opened" << std::endl;
    return -1;
}

int rfe::set_attenuation(int attenuation)
{
    if (rfe_dev) {
        int error = 0;
        if (attenuation > 7) {
            std::cout << "LimeRFE: attenuation value too high, valid range [0, 7]"
                      << std::endl;
            return -1;
        }
        std::cout << "LimeRFE: changing attenuation value to: " << attenuation
                  << std::endl;
        ;

        boardState.attValue = attenuation;
        if ((error = RFE_ConfigureState(rfe_dev, boardState)) != 0) {
            std::cout << "LimeRFE: failed to change attenuation: ";
            print_error(error);
        }
        return error;
    }
    std::cout << "LimeRFE: no RFE device opened" << std::endl;
    return -1;
}

int rfe::set_notch(int enable)
{
    if (rfe_dev) {
        if (boardState.channelIDRX > RFE_CID_HAM_0920 ||
            boardState.channelIDRX == RFE_CID_WB_4000) {
            std::cout << "LimeRFE: notch filter cannot be se for this RX channel"
                      << std::endl;
            return -1;
        }
        int error = 0; //! TODO: might need renaming
        boardState.notchOnOff = enable;
        std::string en_dis[2] = { "disabling", "enabling" };
        std::cout << "LimeRFE: " << en_dis[enable] << " notch filter" << std::endl;
        if ((error = RFE_ConfigureState(rfe_dev, boardState)) != 0) {
            std::cout << "LimeRFE: failed to change change attenuation: ";
            print_error(error);
        }
        return error;
    }
    return -1;
}
void rfe::print_error(int error)
{
    switch (error) {
    case -4:
        std::cout << "error synchronizing communication" << std::endl;
        break;
    case -3:
        std::cout
            << "non-configurable GPIO pin specified. Only pins 4 and 5 are configurable."
            << std::endl;
        break;
    case -2:
        std::cout << "couldn't read the .ini configuration file" << std::endl;
        break;
    case -1:
        std::cout << "communication error" << std::endl;
        break;
    case 1:
        std::cout << "wrong TX port - not possible to route selected TX channel"
                  << std::endl;
        break;
    case 2:
        std::cout << "wrong RX port - not possible to route selected RX channel"
                  << std::endl;
        break;
    case 3:
        std::cout << "TX+RX mode cannot be used when same TX and RX port is used"
                  << std::endl;
        break;
    case 4:
        std::cout << "wrong mode for the cellular channel" << std::endl;
        break;
    case 5:
        std::cout << "cellular channels must be the same both for RX and TX" << std::endl;
        break;
    case 6:
        std::cout << "requested channel code is wrong" << std::endl;
        break;
    default:
        std::cout << "error code doesn't match" << std::endl;
        break;
    }
}

} // namespace limesdr
} // namespace gr
