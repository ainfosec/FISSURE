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

#ifndef DEVICE_HANDLER_H
#define DEVICE_HANDLER_H

#include <LimeSuite.h>
#include <cmath>
#include <iostream>
#include <list>
#include <math.h>
#include <mutex>
#include <string>
#include <vector>

#define LMS_CH_0 0
#define LMS_CH_1 1

#define LimeSDR_Mini 1
#define LimeNET_Micro 2
#define LimeSDR_USB 3

#define GR_LIMESDR_VER "2.1.4"

class device_handler {
    private:
    int open_devices = 0;
    // Read device list once flag
    bool list_read = false;
    // Calculate open devices to close them all on close_all_devices
    int device_count;

    struct device {
        // Device address
        lms_device_t* address = NULL;

        // Flags and variables used to check
        // shared settings and blocks usage
        bool source_flag = false;
        bool sink_flag = false;
        int source_channel_mode = -1;
        int sink_channel_mode = -1;
        std::string source_filename;
        std::string sink_filename;
    };

    // Device list
    lms_info_str_t* list = new lms_info_str_t[20];
    // Device vector. Adds devices from the list
    std::vector<device> device_vector;
    // Run close_all_devices once with this flag
    bool close_flag = false;

    device_handler(){};
    device_handler(device_handler const&);
    void operator=(device_handler const&);


    public:
    static device_handler& getInstance() {
        static device_handler instance;
        return instance;
    }
    ~device_handler();

    mutable std::recursive_mutex block_mutex;


    /**
     * Print device error and close all devices.
     *
     * @param   device_number Device number from the list of LMS_GetDeviceList.
     */
    void error(int device_number);

    /**
     * Get device connection handler in order to configure it.
     *
     * @param   device_number Device number from the list of LMS_GetDeviceList.
     */
    lms_device_t* get_device(int device_number);

    /**
     * Connect to the device and create singletone.
     *
     * @param   serial Device serial from the list of LMS_GetDeviceList.
     */
    int open_device(std::string& serial);

    /**
     * Disconnect from the device.
     *
     * @param   device_number Device number from the list of LMS_GetDeviceList.
     *
     * @param   block_type Source block(1), Sink block(2).
     */
    void close_device(int device_number, int block_type);

    /**
     * Disconnect from all devices.
     */
    void close_all_devices();

    /**
     * Check what blocks are used for single device.
     *
     * @param   device_number Device number from the list of LMS_GetDeviceList.
     *
     * @param   block_type Source block(1), Sink block(2).
     *
     * @param   channel_mode Channel A(0), Channel B(1), MIMO(2)
     *
     * @param   filename  Path to file if file switch is turned on.
     */
    void
    check_blocks(int device_number, int block_type, int channel_mode, const std::string& filename);

    /**
     * Load settings from .ini file.
     *
     * @param   device_number Device number from the list of LMS_GetDeviceList.
     *
     * @param   filename Path to file if file switch is turned on.
     * 
     * @param   antenna_tx Pointer to TX antenna, so PA path would be updated in sink block
     */
    void settings_from_file(int device_number, const std::string& filename, int* antenna_tx);

    /**
     * Set used channels
     *
     * @param   device_number Device number from the list of LMS_GetDeviceList.
     *
     * @param   channel_mode  Channel A(0), Channel B(1), MIMO(2)
     *
     * @param   direction  Direction of samples RX(LMS_CH_RX), TX(LMS_CH_RX).
     */
    void enable_channels(int device_number, int channel_mode, bool direction);

    /**
     * Set the same sample rate for both channels.
     *
     * @param   device_number Device number from the list of LMS_GetDeviceList.
     *
     * @param   rate  Sample rate in S/s.
     */
    void set_samp_rate(int device_number, double& rate);

    /**
     * Set oversampling value for both channels
     *
     * @param   device_number Device number from the list of LMS_GetDeviceList.
     *
     * @param   oversample  Oversampling value (0 (default),1,2,4,8,16,32).
     */
    void set_oversampling(int device_number, int oversample);

    /**
     * Set RF frequency of both channels (RX and TX separately).
     *
     * @param   device_number Device number from the list of LMS_GetDeviceList.
     *
     * @param   direction  Direction of samples RX(LMS_CH_RX), TX(LMS_CH_TX).
     *
     * @param   channel selection: A(LMS_CH_0),B(LMS_CH_1).
     *
     * @param   rf_freq  RF frequency in Hz.
     *
     * @return  returns RF frequency in Hz
     */
    double set_rf_freq(int device_number, bool direction, int channel, float rf_freq);

    /**
     * Perform device calibration.
     *
     * @param   device_number Device number from the list of LMS_GetDeviceList.
     *
     * @param   direction  Direction of samples: RX(LMS_CH_RX),TX(LMS_CH_RX).
     *
     * @param   channel  Channel selection: A(LMS_CH_0),B(LMS_CH_1).
     *
     * @param   bandwidth Set calibration bandwidth in Hz.
     *
     */
    void calibrate(int device_number, int direction, int channel, double bandwidth);

    /**
     * Set which antenna is used
     *
     * @param   device_number Device number from the list of LMS_GetDeviceList.
     *
     * @param   channel  Channel selection: A(LMS_CH_0),B(LMS_CH_1).
     *
     * @param   direction  Direction of samples: RX(LMS_CH_RX),TX(LMS_CH_RX).
     *
     * @param   antenna Antenna to set: None(0), LNAH(1), LNAL(2), LNAW(3) for RX
     *                                  None(0), BAND1(1), BAND(2), NONE(3) for TX
     *
     */
    void set_antenna(int device_number, int channel, int direction, int antenna);

    /**
     * Set analog filters.
     *
     * @param   device_number Device number from the list of LMS_GetDeviceList.
     *
     * @param   direction  Direction of samples: RX(LMS_CH_RX),TX(LMS_CH_TX).
     *
     * @param   channel  Channel selection: A(LMS_CH_0),B(LMS_CH_1).
     *
     * @param   analog_bandw  Channel filter bandwidth in Hz.
     */
    double set_analog_filter(int device_number, bool direction, int channel, double analog_bandw);

    /**
     * Set digital filters (GFIR).
     *
     * @param   device_number Device number from the list of LMS_GetDeviceList.
     *
     * @param   direction  Direction of samples: RX(LMS_CH_RX),TX(LMS_CH_TX).
     *
     * @param   channel  Channel selection: A(LMS_CH_0),B(LMS_CH_1).
     *
     * @param   digital_bandw  Channel filter bandwidth in Hz.
     */
    double set_digital_filter(int device_number, bool direction, int channel, double digital_bandw);

    /**
     * Set the combined gain value in dB
     * This function computes and sets the optimal gain values of various amplifiers
     * that are present in the device based on desired  gain value in dB.
     *
     * @note actual gain depends on LO frequency and analog LPF configuration and
     * resulting output signal level may be different when those values are changed
     *
     * @param   device_number  Device number from the list of LMS_GetDeviceList.
     *
     * @param   direction      Select RX or TX.
     *
     * @param   channel        Channel selection: A(LMS_CH_0),B(LMS_CH_1).
     *
     * @param   gain_dB        Desired gain: [0,70] RX, [0,60] TX.
     */
    unsigned set_gain(int device_number, bool direction, int channel, unsigned gain_dB);

    /**
     * Set NCO (numerically controlled oscillator).
     * By selecting NCO frequency
     * configure NCO. When NCO frequency is 0, NCO is off.
     *
     * @param   device_number  Device number from the list of LMS_GetDeviceList.
     *
     * @param   direction      Select RX or TX.
     *
     * @param   channel        Channel index.
     *
     * @param   nco_freq       NCO frequency in Hz.
     */
    void set_nco(int device_number, bool direction, int channel, float nco_freq);

    void disable_DC_corrections(int device_number);

    /**
     * Set TCXO DAC.
     * @note Care must be taken as this parameter is returned to default value only after power off.
     * @note LimeSDR-Mini default value is 180 range is [0,255]
     * LimeSDR-USB default value is 125 range is [0,255]
     * LimeSDR-PCIe default value is 134 range is [0,255]
     * LimeNET-Micro default value is 30714 range is [0,65535]
     * 
     * @param   device_number  Device number from the list of LMS_GetDeviceList.
     *
     * @param   dacVal		   DAC value (0-65535)
     */
    void set_tcxo_dac(int device_number, uint16_t dacVal);

};


#endif
