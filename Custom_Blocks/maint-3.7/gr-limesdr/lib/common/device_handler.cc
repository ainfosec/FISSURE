/* -*- c++ -*- */
/*
 * Copyright 2018 Lime Microsystems info@limemicro.com
 *
 * GNU Radio is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3, or (at your option)
 * any later version.
 *
 * GNU Radio is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GNU Radio; see the file COPYING.  If not, write to
 * the Free Software Foundation, Inc., 51 Franklin Street,
 * Boston, MA 02110-1301, USA.
 */

#include "device_handler.h"
#include <LMS7002M_parameters.h>

device_handler::~device_handler() { delete list; }

void device_handler::error(int device_number) {
    // std::cout << "ERROR: " << LMS_GetLastErrorMessage() << std::endl;
    if (this->device_vector[device_number].address != NULL)
        close_all_devices();
}

lms_device_t* device_handler::get_device(int device_number) {
    return this->device_vector[device_number].address;
}

int device_handler::open_device(std::string& serial) {

    int device_number;
    std::string search_name;
    std::cout << "##################" << std::endl;
    std::cout << "Connecting to device" << std::endl;

    // Print device and library information only once
    if (list_read == false) {
        std::cout << "##################" << std::endl;
        std::cout << "LimeSuite version: " << LMS_GetLibraryVersion() << std::endl;
        std::cout << "gr-limesdr version: " << GR_LIMESDR_VER << std::endl;
        std::cout << "##################" << std::endl;

        device_count = LMS_GetDeviceList(list);
        if (device_count < 1) {
            std::cout << "ERROR: device_handler::open_device(): No Lime devices found."
                      << std::endl;
            exit(0);
        }
        std::cout << "Device list:" << std::endl;

        for (int i = 0; i < device_count; i++) {
            std::cout << "Nr.:" << i << " device:" << list[i] << std::endl;
            device_vector.push_back(device());
        }
        std::cout << "##################" << std::endl;
        list_read = true;
    }

    if (serial.empty()) {
        std::cout << "INFO: device_handler::open_device(): no serial number. Using first device in "
                     "the list."
                  << std::endl
                  << "Use \"LimeUtil --find\" in terminal to find prefered device serial."
                  << std::endl;
    }

    // Identify device by serial number
    for (int i = 0; i < device_count; i++) {
        std::string device_string(list[i]);
        size_t first = device_string.find("serial=") + 7;
        size_t end = device_string.find(",", first);
        std::string aquired_serial = device_string.substr(first, end - first);

        // If serial is left empty, use first device in list
        if (serial.empty()) {
            device_number = i;
            serial = aquired_serial;
            break;
        } else if (aquired_serial == serial) {
            device_number = i;
            break;
        }
        // If program was unable to find device in list print error and stop program
        else if (i == device_count - 1 && (aquired_serial != serial)) {
            std::cout << "Unable to find LMS device with serial " << serial << "." << std::endl;
            std::cout << "##################" << std::endl;
            close_all_devices();
        }
    }

    // If device slot is empty, open and initialize device
    if (device_vector[device_number].address == NULL) {
        if (LMS_Open(&device_vector[device_number].address, list[device_number], NULL) !=
            LMS_SUCCESS)
            exit(0);
        LMS_Init(device_vector[device_number].address);
        const lms_dev_info_t* info = LMS_GetDeviceInfo(device_vector[device_number].address);
        std::cout << "Using device: " << info->deviceName << "(" << serial
                  << ") GW: " << info->gatewareVersion << " FW: " << info->firmwareVersion
                  << std::endl;
        ++open_devices; // Count open devices
        std::cout << "##################" << std::endl;
        std::cout << std::endl;
    }
    // If device is open do nothing
    else {
        std::cout << "Previously connected device number " << device_number
                  << " from the list is used." << std::endl;
        std::cout << "##################" << std::endl;
        std::cout << std::endl;
    }


    return device_number; // return device number to identify device_vector[device_number].address
                          // connection in other functions
}

void device_handler::close_device(int device_number, int block_type) {
    // Check if other block finished and close device
    if (device_vector[device_number].source_flag == false ||
        device_vector[device_number].sink_flag == false) {
        if (device_vector[device_number].address != NULL) {
            std::cout << std::endl;
            std::cout << "##################" << std::endl;
            if (LMS_Reset(this->device_vector[device_number].address) != LMS_SUCCESS)
                error(device_number);
            if (LMS_Close(this->device_vector[device_number].address) != LMS_SUCCESS)
                error(device_number);
            std::cout << "INFO: device_handler::close_device(): Disconnected from device number "
                      << device_number << "." << std::endl;
            device_vector[device_number].address = NULL;
            std::cout << "##################" << std::endl;
            std::cout << std::endl;
        }
    }
    // If two blocks used switch one block flag and let other block finish work
    // Switch flag when closing device
    switch (block_type) {
    case 1:
        device_vector[device_number].source_flag = false;
        break;
    case 2:
        device_vector[device_number].sink_flag = false;
        break;
    }
}

void device_handler::close_all_devices() {
    if (close_flag == false) {
        for (int i = 0; i <= open_devices; i++) {
            if (this->device_vector[i].address != NULL) {
                LMS_Reset(this->device_vector[i].address);
                LMS_Close(this->device_vector[i].address);
            }
        }
        close_flag = true;
        exit(0);
    }
}

void device_handler::check_blocks(int device_number,
                                  int block_type,
                                  int channel_mode,
                                  const std::string& filename) {
    // Get each block settings
    switch (block_type) {
    case 1: // Source block
        if (device_vector[device_number].source_flag == true) {
            std::cout << "ERROR: device_handler::check_blocks(): only one LimeSuite Source (RX) "
                         "block is allowed per device."
                      << std::endl;
            close_all_devices();
        } else {
            device_vector[device_number].source_flag = true;
            device_vector[device_number].source_channel_mode = channel_mode;
            device_vector[device_number].source_filename = filename;
        }
        break;

    case 2: // Sink block
        if (device_vector[device_number].sink_flag == true) {
            std::cout << "ERROR: device_handler::check_blocks(): only one LimeSuite Sink (TX) "
                         "block is allowed per device."
                      << std::endl;
            close_all_devices();
        } else {
            device_vector[device_number].sink_flag = true;
            device_vector[device_number].sink_channel_mode = channel_mode;
            device_vector[device_number].sink_filename = filename;
        }
        break;

    default:
        std::cout << "ERROR: device_handler::check_blocks(): incorrect block_type value."
                  << std::endl;
        close_all_devices();
    }

    // Check block settings which must match
    if (device_vector[device_number].source_flag && device_vector[device_number].sink_flag) {
        // Chip_mode must match in blocks with the same serial
        if (device_vector[device_number].source_channel_mode !=
            device_vector[device_number].sink_channel_mode) {
            std::cout << "Source: " << device_vector[device_number].source_channel_mode
                      << std::endl;
            std::cout << "Sink: " << device_vector[device_number].sink_channel_mode << std::endl;
            std::cout << "ERROR: device_handler::check_blocks(): channel mismatch in LimeSuite "
                         "Source (RX) and LimeSuite Sink (TX)."
                      << std::endl;
            close_all_devices();
        }

        // When file_switch is 1 check filename match throughout the blocks with the same serial
        if (device_vector[device_number].source_filename !=
            device_vector[device_number].sink_filename) {
            std::cout << "ERROR: device_handler::check_blocks(): file must match in LimeSuite "
                         "Source (RX) and LimeSuite Sink (TX)."
                      << std::endl;
            close_all_devices();
        }
    }
}

void device_handler::settings_from_file(int device_number,
                                        const std::string& filename,
                                        int* pAntenna_tx) {
    if (LMS_LoadConfig(device_handler::getInstance().get_device(device_number), filename.c_str()))
        device_handler::getInstance().error(device_number);

    // Set LimeSDR-Mini switches based on .ini file
    int antenna_rx = LMS_PATH_NONE;
    int antenna_tx[2] = {LMS_PATH_NONE};
    antenna_tx[0] = LMS_GetAntenna(
        device_handler::getInstance().get_device(device_number), LMS_CH_TX, LMS_CH_0);
    /* Don't print error message for the mini board */
    LMS_RegisterLogHandler([](int, const char*) {});
    antenna_tx[1] = LMS_GetAntenna(
        device_handler::getInstance().get_device(device_number), LMS_CH_TX, LMS_CH_1);
    LMS_RegisterLogHandler(nullptr);
    antenna_rx = LMS_GetAntenna(
        device_handler::getInstance().get_device(device_number), LMS_CH_RX, LMS_CH_0);

    if (pAntenna_tx != nullptr) {
        pAntenna_tx[0] = antenna_tx[0];
        pAntenna_tx[1] = antenna_tx[1];
    }

    LMS_SetAntenna(device_handler::getInstance().get_device(device_number),
                   LMS_CH_TX,
                   LMS_CH_0,
                   antenna_tx[0]);
    LMS_SetAntenna(
        device_handler::getInstance().get_device(device_number), LMS_CH_RX, LMS_CH_0, antenna_rx);
}

void device_handler::enable_channels(int device_number, int channel_mode, bool direction) {
    std::cout << "INFO: device_handler::enable_channels(): ";
    if (channel_mode < 2) {

        if (LMS_EnableChannel(device_handler::getInstance().get_device(device_number),
                              direction,
                              channel_mode,
                              true) != LMS_SUCCESS)
            device_handler::getInstance().error(device_number);
        std::cout << "SISO CH" << channel_mode << " set for device number " << device_number << "."
                  << std::endl;
    } else if (channel_mode == 2) {
        if (LMS_EnableChannel(device_handler::getInstance().get_device(device_number),
                              direction,
                              LMS_CH_0,
                              true) != LMS_SUCCESS)
            device_handler::getInstance().error(device_number);
        if (LMS_EnableChannel(device_handler::getInstance().get_device(device_number),
                              direction,
                              LMS_CH_1,
                              true) != LMS_SUCCESS)
            device_handler::getInstance().error(device_number);
        std::cout << "MIMO mode set for device number " << device_number << "." << std::endl;
    }
}

void device_handler::set_samp_rate(int device_number, double& rate) {
    std::cout << "INFO: device_handler::set_samp_rate(): ";
    if (LMS_SetSampleRate(device_handler::getInstance().get_device(device_number), rate, 0) !=
        LMS_SUCCESS)
        device_handler::getInstance().error(device_number);
    double host_value;
    double rf_value;
    if (LMS_GetSampleRate(device_handler::getInstance().get_device(device_number),
                          LMS_CH_RX,
                          LMS_CH_0,
                          &host_value,
                          &rf_value))
        device_handler::getInstance().error(device_number);
    std::cout << "set sampling rate: " << host_value / 1e6 << " MS/s." << std::endl;
    rate = host_value; // Get the real rate back;
}

void device_handler::set_oversampling(int device_number, int oversample) {
    if (oversample == 0 || oversample == 1 || oversample == 2 || oversample == 4 ||
        oversample == 8 || oversample == 16 || oversample == 32) {
        std::cout << "INFO: device_handler::set_oversampling(): ";
        double host_value;
        double rf_value;
        if (LMS_GetSampleRate(device_handler::getInstance().get_device(device_number),
                              LMS_CH_RX,
                              LMS_CH_0,
                              &host_value,
                              &rf_value))
            device_handler::getInstance().error(device_number);

        if (LMS_SetSampleRate(device_handler::getInstance().get_device(device_number),
                              host_value,
                              oversample) != LMS_SUCCESS)
            device_handler::getInstance().error(device_number);

        std::cout << "Oversampling set to: " << oversample << std::endl;
    } else {
        std::cout << "ERROR: device_handler::set_oversampling(): valid oversample values are: "
                     "0,1,2,4,8,16,32."
                  << std::endl;
        close_all_devices();
    }
}

double device_handler::set_rf_freq(int device_number, bool direction, int channel, float rf_freq) {
    if (rf_freq <= 0) {
        std::cout << "ERROR: device_handler::set_rf_freq(): rf_freq must be more than 0 Hz."
                  << std::endl;
        close_all_devices();
    } else {
        std::cout << "INFO: device_handler::set_rf_freq(): ";
        if (LMS_SetLOFrequency(device_handler::getInstance().get_device(device_number),
                               direction,
                               channel,
                               rf_freq) != LMS_SUCCESS)
            device_handler::getInstance().error(device_number);

        double value = 0;
        LMS_GetLOFrequency(
            device_handler::getInstance().get_device(device_number), direction, channel, &value);

        std::string s_dir[2] = {"RX", "TX"};
        std::cout << "RF frequency set [" << s_dir[direction] << "]: " << value / 1e6 << " MHz."
                  << std::endl;
        return value;
    }
}

void device_handler::calibrate(int device_number, int direction, int channel, double bandwidth) {
    std::cout << "INFO: device_handler::calibrate(): ";
    double rf_freq = 0;
    LMS_GetLOFrequency(
        device_handler::getInstance().get_device(device_number), direction, channel, &rf_freq);
    if (rf_freq > 31e6) // Normal calibration
        LMS_Calibrate(device_handler::getInstance().get_device(device_number),
                      direction,
                      channel,
                      bandwidth,
                      0);
    else { // Workaround
        LMS_SetLOFrequency(
            device_handler::getInstance().get_device(device_number), direction, channel, 50e6);
        LMS_Calibrate(device_handler::getInstance().get_device(device_number),
                      direction,
                      channel,
                      bandwidth,
                      0);
        LMS_SetLOFrequency(
            device_handler::getInstance().get_device(device_number), direction, channel, rf_freq);
    }
}

void device_handler::set_antenna(int device_number, int channel, int direction, int antenna) {
    std::cout << "INFO: device_handler::set_antenna(): ";
    LMS_SetAntenna(
        device_handler::getInstance().get_device(device_number), direction, channel, antenna);
    int antenna_value =
        LMS_GetAntenna(device_handler::getInstance().get_device(device_number), direction, channel);

    std::string s_antenna[2][4] = {{"Auto(NONE)", "LNAH", "LNAL", "LNAW"},
                                   {"Auto(NONE)", "BAND1", "BAND2", "NONE"}};
    std::string s_dir[2] = {"RX", "TX"};

    std::cout << "CH" << channel << " antenna set [" << s_dir[direction]
              << "]: " << s_antenna[direction][antenna_value] << "." << std::endl;
}

double device_handler::set_analog_filter(int device_number,
                                         bool direction,
                                         int channel,
                                         double analog_bandw) {
    if (channel == 0 || channel == 1) {
        if (direction == LMS_CH_TX || direction == LMS_CH_RX) {
            std::cout << "INFO: device_handler::set_analog_filter(): ";
            LMS_SetLPFBW(device_handler::getInstance().get_device(device_number),
                         direction,
                         channel,
                         analog_bandw);

            double analog_value;
            LMS_GetLPFBW(device_handler::getInstance().get_device(device_number),
                         direction,
                         channel,
                         &analog_value);
            return analog_value;
        } else {
            std::cout << "ERROR: device_handler::set_analog_filter(): direction must be "
                         "0(LMS_CH_RX) or 1(LMS_CH_TX)."
                      << std::endl;
            close_all_devices();
        }
    } else {
        std::cout << "ERROR: device_handler::set_analog_filter(): channel must be 0 or 1."
                  << std::endl;
        close_all_devices();
    }
}

double device_handler::set_digital_filter(int device_number,
                                          bool direction,
                                          int channel,
                                          double digital_bandw) {
    if (channel == 0 || channel == 1) {
        if (direction == LMS_CH_TX || direction == LMS_CH_RX) {
            bool enable = (digital_bandw > 0) ? true : false;
            std::cout << "INFO: device_handler::set_digital_filter(): ";
            LMS_SetGFIRLPF(device_handler::getInstance().get_device(device_number),
                           direction,
                           channel,
                           enable,
                           digital_bandw);
            std::string s_dir[2] = {"RX", "TX"};
            std::cout << "digital filter CH" << channel << " [" << s_dir[direction] << "]: ";
            if (enable)
                std::cout << digital_bandw / 1e6 << " MHz." << std::endl;
            else
                std::cout << "disabled" << std::endl;
            return digital_bandw;
        } else {
            std::cout << "ERROR: device_handler::set_digital_filter(): direction must be "
                         "0(LMS_CH_RX) or 1(LMS_CH_TX)."
                      << std::endl;
            close_all_devices();
        }
    } else {
        std::cout << "ERROR: device_handler::set_digital_filter(): channel must be 0 or 1."
                  << std::endl;
        close_all_devices();
    }
}

unsigned
device_handler::set_gain(int device_number, bool direction, int channel, unsigned gain_dB) {
    if ((direction == LMS_CH_RX && gain_dB >= 0 && gain_dB <= 70) ||
        (direction == LMS_CH_TX && gain_dB >= 0 && gain_dB <= 60)) {
        std::cout << "INFO: device_handler::set_gain(): ";
        LMS_SetGaindB(
            device_handler::getInstance().get_device(device_number), direction, channel, gain_dB);

        std::string s_dir[2] = {"RX", "TX"};

        unsigned int gain_value;
        LMS_GetGaindB(device_handler::getInstance().get_device(device_number),
                      direction,
                      channel,
                      &gain_value);
        std::cout << "set gain [" << s_dir[direction] << "] CH" << channel << ": " << gain_value
                  << " dB." << std::endl;
        return gain_value;
    } else {
        std::cout << "ERROR: device_handler::set_gain(): valid RX gain range [0, 70], TX gain "
                     "range [0, 60]."
                  << std::endl;
        close_all_devices();
    }
}

void device_handler::set_nco(int device_number, bool direction, int channel, float nco_freq) {
    std::string s_dir[2] = {"RX", "TX"};
    std::cout << "INFO: device_handler::set_nco(): ";
    if (nco_freq == 0) {
        LMS_SetNCOIndex(
            device_handler::getInstance().get_device(device_number), direction, channel, -1, 0);
        std::cout << "NCO [" << s_dir[direction] << "] CH" << channel << " disabled" << std::endl;
    } else {
        double freq_value_in[16] = {nco_freq};
        int cmix_mode;

        if (nco_freq > 0)
            cmix_mode = 0;
        else if (nco_freq < 0)
            cmix_mode = 1;

        LMS_SetNCOFrequency(device_handler::getInstance().get_device(device_number),
                            direction,
                            channel,
                            freq_value_in,
                            0);
        LMS_SetNCOIndex(device_handler::getInstance().get_device(device_number),
                        direction,
                        channel,
                        0,
                        cmix_mode);
        std::string s_cmix[2] = {"UPCONVERT", "DOWNCONVERT"};
        std::string cmix_mode_string;

        double freq_value_out[16];
        double pho_value_out[16];
        LMS_GetNCOFrequency(device_handler::getInstance().get_device(device_number),
                            direction,
                            channel,
                            freq_value_out,
                            pho_value_out);
        std::cout << "NCO [" << s_dir[direction] << "] CH" << channel << ": "
                  << freq_value_out[0] / 1e6 << " MHz (" << pho_value_out[0] << " deg.)("
                  << s_cmix[cmix_mode] << ")." << std::endl;
    }
}

void device_handler::disable_DC_corrections(int device_number) {
    LMS_WriteParam(device_handler::getInstance().get_device(device_number), LMS7_DC_BYP_RXTSP, 1);
    LMS_WriteParam(device_handler::getInstance().get_device(device_number), LMS7_DCLOOP_STOP, 1);
}

void device_handler::set_tcxo_dac(int device_number, uint16_t dacVal) {
    if (dacVal >= 0 && dacVal <= 65535) {
        std::cout << "INFO: device_handler::set_tcxo_dac(): ";
        float_type dac_value = dacVal;

        LMS_WriteCustomBoardParam(
            device_handler::getInstance().get_device(device_number), BOARD_PARAM_DAC, dacVal, NULL);

        LMS_ReadCustomBoardParam(device_handler::getInstance().get_device(device_number),
                                 BOARD_PARAM_DAC,
                                 &dac_value,
                                 NULL);

        std::cout << "VCTCXO DAC value set to: " << dac_value << std::endl;
    } else {
        std::cout << "ERROR: device_handler::set_tcxo_dac(): valid range [0, 65535]" << std::endl;
        close_all_devices();
    }
}
