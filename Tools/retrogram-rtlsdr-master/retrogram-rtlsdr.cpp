/*

          _                                      /\/|    _   _ _________________
         | |                                    |/\/    | | | /  ___|  _  \ ___ \
 _ __ ___| |_ _ __ ___   __ _ _ __ __ _ _ __ ___    _ __| |_| \ `--.| | | | |_/ /
| '__/ _ \ __| '__/ _ \ / _` | '__/ _` | '_ ` _ \  | '__| __| |`--. \ | | |    /
| | |  __/ |_| | | (_) | (_| | | | (_| | | | | | | | |  | |_| /\__/ / |/ /| |\ \
|_|  \___|\__|_|  \___/ \__, |_|  \__,_|_| |_| |_| |_|   \__|_\____/|___/ \_| \_|
                         __/ |
                        |___/

Wideband Spectrum analyzer on your terminal/ssh console with ASCII art.
Hacked from Ettus UHD RX ASCII Art DFT code - adapted for RTL SDR dongle.

*/
//
// Copyright 2010-2011,2014 Ettus Research LLC
// Copyright 2018 Ettus Research, a National Instruments Company
// Copyright 2020 Erik Henriksson
//
// SPDX-License-Identifier: GPL-3.0-or-later
//


#include "ascii_art_dft.hpp" //implementation
#include <boost/program_options.hpp>
#include <boost/format.hpp>
#include <curses.h>
#include <iostream>
#include <complex>
#include <cstdlib>
#include <chrono>
#include <thread>

#include <rtl-sdr.h>

#define EXIT_ON_ERR false
#define DISABLE_STDERR true

namespace po = boost::program_options;
using std::chrono::high_resolution_clock;

static rtlsdr_dev_t *dev = NULL;

void exiterr(int retcode)
{
    if (EXIT_ON_ERR) exit(retcode);
}

// Convenience functions from librtlsdr - (C) 2014 by Kyle Keen <keenerd@gmail.com>

int verbose_set_frequency(rtlsdr_dev_t *dev, uint32_t frequency)
{
    int r;
    r = rtlsdr_set_center_freq(dev, frequency);
    if (r < 0) {
        fprintf(stderr, "WARNING: Failed to set center freq.\n");
        exiterr(0);
    } else {
        fprintf(stderr, "Tuned to %u Hz.\n", frequency);
    }
    return r;
}

int verbose_set_sample_rate(rtlsdr_dev_t *dev, uint32_t samp_rate)
{
    int r;
    r = rtlsdr_set_sample_rate(dev, samp_rate);
    if (r < 0) {
        fprintf(stderr, "WARNING: Failed to set sample rate.\n");
        exiterr(0);
    } else {
        fprintf(stderr, "Sampling at %u S/s.\n", samp_rate);
    }
    return r;
}

int nearest_gain(rtlsdr_dev_t *dev, int target_gain)
{
    int i, r, err1, err2, count, nearest;
    int* gains;
    r = rtlsdr_set_tuner_gain_mode(dev, 1);
    if (r < 0) {
        fprintf(stderr, "WARNING: Failed to enable manual gain.\n");
        return r;
    }
    count = rtlsdr_get_tuner_gains(dev, NULL);
    if (count <= 0) {
        return 0;
    }
    gains = (int *)malloc(sizeof(int) * count);
    count = rtlsdr_get_tuner_gains(dev, gains);
    nearest = gains[0];
    for (i=0; i<count; i++) {
        err1 = abs(target_gain - nearest);
        err2 = abs(target_gain - gains[i]);
        if (err2 < err1) {
            nearest = gains[i];
        }
    }
    free(gains);
    return nearest;
}


int verbose_auto_gain(rtlsdr_dev_t *dev)
{
    int r;
    r = rtlsdr_set_tuner_gain_mode(dev, 0);
    if (r != 0) {
        fprintf(stderr, "WARNING: Failed to set tuner gain.\n");
        exiterr(0);
    } else {
        fprintf(stderr, "Tuner gain set to automatic.\n");
    }
    return r;
}

int verbose_gain_set(rtlsdr_dev_t *dev, int gain)
{
    int r;
    r = rtlsdr_set_tuner_gain_mode(dev, 1);
    if (r < 0) {
        fprintf(stderr, "WARNING: Failed to enable manual gain.\n");
        return r;
    }
    r = rtlsdr_set_tuner_gain(dev, gain);
    if (r != 0) {
        fprintf(stderr, "WARNING: Failed to set tuner gain.\n");
        exiterr(0);
    } else {
        fprintf(stderr, "Tuner gain set to %0.2f dB.\n", gain/10.0);
    }
    return r;
}

int verbose_reset_buffer(rtlsdr_dev_t *dev)
{
    int r;
    r = rtlsdr_reset_buffer(dev);
    if (r < 0) {
        fprintf(stderr, "WARNING: Failed to reset buffers.\n");
        exiterr(0);
    }
    return r;
}

int verbose_device_search(const char *s)
{
    int i, device_count, device, offset;
    char *s2;
    char vendor[256], product[256], serial[256];
    device_count = rtlsdr_get_device_count();
    if (!device_count) {
        fprintf(stderr, "No supported devices found.\n");
        return -1;
    }
    fprintf(stderr, "Found %d device(s):\n", device_count);
    for (i = 0; i < device_count; i++) {
        rtlsdr_get_device_usb_strings(i, vendor, product, serial);
        fprintf(stderr, "  %d:  %s, %s, SN: %s\n", i, vendor, product, serial);
    }
    fprintf(stderr, "\n");
    /* does string look like raw id number */
    device = (int)strtol(s, &s2, 0);
    if (s2[0] == '\0' && device >= 0 && device < device_count) {
        fprintf(stderr, "Using device %d: %s\n",
            device, rtlsdr_get_device_name((uint32_t)device));
        return device;
    }
    /* does string exact match a serial */
    for (i = 0; i < device_count; i++) {
        rtlsdr_get_device_usb_strings(i, vendor, product, serial);
        if (strcmp(s, serial) != 0) {
            continue;}
        device = i;
        fprintf(stderr, "Using device %d: %s\n",
            device, rtlsdr_get_device_name((uint32_t)device));
        return device;
    }
    /* does string prefix match a serial */
    for (i = 0; i < device_count; i++) {
        rtlsdr_get_device_usb_strings(i, vendor, product, serial);
        if (strncmp(s, serial, strlen(s)) != 0) {
            continue;}
        device = i;
        fprintf(stderr, "Using device %d: %s\n",
            device, rtlsdr_get_device_name((uint32_t)device));
        return device;
    }
    /* does string suffix match a serial */
    for (i = 0; i < device_count; i++) {
        rtlsdr_get_device_usb_strings(i, vendor, product, serial);
        offset = strlen(serial) - strlen(s);
        if (offset < 0) {
            continue;}
        if (strncmp(s, serial+offset, strlen(s)) != 0) {
            continue;}
        device = i;
        fprintf(stderr, "Using device %d: %s\n",
            device, rtlsdr_get_device_name((uint32_t)device));
        return device;
    }
    fprintf(stderr, "No matching devices found.\n");
    return -1;
}


int main(int argc, char *argv[]){

    //variables to be set by po
    std::string dev_id;

    int dev_index, rtl_inst, n_read;

    uint8_t *buffer;

    int num_bins = 512;
    double rate, freq, step, gain, ngain, frame_rate;
    float ref_lvl, dyn_rng;
    bool show_controls;
    bool peak_hold;

    int ch;
    bool loop = true;

    //setup the program options
    po::options_description desc("\nAllowed options");
    desc.add_options()
        ("help", "help message")
        ("dev", po::value<std::string>(&dev_id)->default_value("0"), "rtl-sdr device index")
        // hardware parameters
        ("rate", po::value<double>(&rate)->default_value(1e6), "rate of incoming samples (sps) [r-R]")
        ("freq", po::value<double>(&freq)->default_value(100e6), "RF center frequency in Hz [f-F]")
        ("gain", po::value<double>(&gain)->default_value(0), "gain for the RF chain [g-G]")
        // display parameters
        ("frame-rate", po::value<double>(&frame_rate)->default_value(15), "frame rate of the display (fps) [s-S]")
        ("peak-hold", po::value<bool>(&peak_hold)->default_value(false), "enable peak hold [h-H]")
        ("ref-lvl", po::value<float>(&ref_lvl)->default_value(0), "reference level for the display (dB) [l-L]")
        ("dyn-rng", po::value<float>(&dyn_rng)->default_value(80), "dynamic range for the display (dB) [d-D]")
        ("step", po::value<double>(&step)->default_value(1e5), "tuning step for rate/bw/freq [t-T]")
        ("show-controls", po::value<bool>(&show_controls)->default_value(true), "show the keyboard controls")
    ;
    po::variables_map vm;
    po::store(po::parse_command_line(argc, argv, desc), vm);
    po::notify(vm);

    std::cout << boost::format("retrogram~rtlsdr - ASCII Art Spectrum Analysis for RTLSDR") << std::endl;

    //print the help message
    if (vm.count("help") or vm.count("h")){
        std::cout << boost::format("%s") % desc << std::endl;
        return EXIT_FAILURE;
    }

    //create pluto device instance
    std::cout << std::endl;
    std::cout << boost::format("Creating the rtlsdr device instance: %s...") % dev_index << std::endl << std::endl;

    dev_index = verbose_device_search(dev_id.c_str());

    if (dev_index < 0) {
        return EXIT_FAILURE;
    }

    rtl_inst = rtlsdr_open(&dev, (uint32_t)dev_index);
    if (rtl_inst < 0) {
        fprintf(stderr, "Failed to open rtlsdr device #%d.\n", dev_index);
        return EXIT_FAILURE;
    }


    //set the sample rate
    std::cout << boost::format("Setting RX Rate: %f Msps...") % (rate/1e6) << std::endl;
    verbose_set_sample_rate(dev, rate);

    //set the center frequency
    std::cout << boost::format("Setting RX Freq: %f MHz...") % (freq/1e6) << std::endl;
    verbose_set_frequency(dev, freq);

    //set the rf gain
    if (0 == gain) {
         /* Enable automatic gain */
        verbose_auto_gain(dev);
        std::cout << boost::format("Setting RX Gain: auto...") << std::endl ;
    } else {
        /* Enable manual gain */
        gain *= 10;
        ngain = nearest_gain(dev, gain);
        verbose_gain_set(dev, ngain);
        std::cout << boost::format("Setting RX Gain: %f dB...") % gain;
    }

    std::this_thread::sleep_for(std::chrono::seconds(1)); //allow for some setup time

    std::vector<std::complex<float> > buff(num_bins);

    buffer = (uint8_t*)malloc(num_bins * 2 * sizeof(uint8_t));

    /* Reset endpoint before we start reading from it (mandatory) */
    verbose_reset_buffer(dev);


    //------------------------------------------------------------------
    //-- Initialize
    //------------------------------------------------------------------
    initscr();

    auto next_refresh = high_resolution_clock::now();

    //disable stderr on ncurses screen
    if (DISABLE_STDERR) freopen("/dev/null", "w", stderr);


    float i,q;

    //------------------------------------------------------------------
    //-- Main loop
    //------------------------------------------------------------------

    ascii_art_dft::log_pwr_dft_type last_lpdft;

    while (loop){

        buff.clear();

        rtl_inst = rtlsdr_read_sync(dev, buffer, num_bins * 2, &n_read);
        if (rtl_inst < 0)
        {
               fprintf(stderr, "WARNING: sync read failed.\n");
               break;
        }

        if (n_read < (num_bins * 2))
        {
                fprintf(stderr, "Short read, samples lost, exiting!\n");
                break;
        }

        for(int j = 0; j < (num_bins * 2); j+=2)
        {
            i = (((float)buffer[j] - 127.5)/128);
            q = (((float)buffer[j+1] - 127.5)/128);

            buff.push_back(std::complex<float> ( i,  q ));
        }

        // Return early to save CPU if peak hold is disabled and no refresh is required.
        if (!peak_hold && high_resolution_clock::now() < next_refresh) {
            continue;
        }

        //calculate the dft and create the ascii art frame
        ascii_art_dft::log_pwr_dft_type lpdft(
            ascii_art_dft::log_pwr_dft(&buff.front(), buff.size())
        );

        // For peak hold, compute the max of last DFT and current one
        if (peak_hold && last_lpdft.size() == lpdft.size()) {
            for (size_t i = 0; i < lpdft.size(); ++i) {
                lpdft[i] = std::max(lpdft[i], last_lpdft[i]);
            }
        }
        last_lpdft = lpdft;

        //check and update the display refresh condition
        if (high_resolution_clock::now() < next_refresh) {
            continue;
        }
        next_refresh =
            high_resolution_clock::now()
            + std::chrono::microseconds(int64_t(1e6/frame_rate));

        std::string frame = ascii_art_dft::dft_to_plot(
            lpdft, COLS, (show_controls ? LINES-5 : LINES),
            rate,
            freq,
            dyn_rng, ref_lvl
        );

        std::string header = std::string((COLS-26)/2, '-');
    	std::string border = std::string((COLS), '-');

        //curses screen handling: clear and print frame
        clear();
        if (show_controls)
        {
            printw("-%s-={ retrogram~rtlsdr }=-%s--",header.c_str(),header.c_str());
            printw("[f-F]req: %4.3f MHz   |   [r-R]ate: %2.2f Msps   |    ", freq/1e6, rate/1e6);
            if (gain == 0) printw("[g-G]ain: (Auto)");
            else printw("[g-G]ain: %2.0f dB", gain/10);
            printw("   |    Peak [h-H]hold: %s\n\n", peak_hold ? "On" : "Off");
            printw("[d-D]yn Range: %2.0f dB    |   Ref [l-L]evel: %2.0f dB   |   fp[s-S] : %2.0f   |   [t-T]uning step: %3.3f M\n", dyn_rng, ref_lvl, frame_rate, step/1e6);
    	    printw("%s", border.c_str());
        }
        printw("%s\n", frame.c_str());

        //curses key handling: no timeout, any key to exit
        timeout(0);
        ch = getch();

        switch(ch)
        {
            case 'r':
            {
                if ((rate - step) > 0)
                {
                    rate -= step;
                    verbose_set_sample_rate(dev, rate);
                }
                break;
            }

            case 'R':
            {
                if ((rate + step) < 2.4e6)
                {
                    rate += step;
                    verbose_set_sample_rate(dev, rate);
                }
                break;
            }

            case 'g':
            {
                if ((gain-10) > 1)
                {
                    gain -= 10;
                    ngain = nearest_gain(dev, gain);
                    verbose_gain_set(dev, ngain);
                }
                break;
            }

            case 'G':
            {
                if ((gain + 10) < 500)
                {
                    gain += 10;
                    ngain = nearest_gain(dev, gain);
                    verbose_gain_set(dev, ngain);
                }
                break;
            }

            case 'f':
            {
                freq -= step;
                verbose_set_frequency(dev, freq);
                break;
            }

            case 'F':
            {
                freq += step;
                verbose_set_frequency(dev, freq);
                break;
            }

            case 'h': { peak_hold = false; break; }
            case 'H': { peak_hold = true; break; }
            case 'l': { ref_lvl -= 10; break; }
            case 'L': { ref_lvl += 10; break; }
            case 'd': { dyn_rng -= 10; break; }
            case 'D': { dyn_rng += 10; break; }
            case 's': { if (frame_rate > 1) frame_rate -= 1; break;}
            case 'S': { frame_rate += 1; break; }
            case 't': { if (step > 1) step /= 2; break; }
            case 'T': { step *= 2; break; }
            case 'c': { show_controls = false; break; }
            case 'C': { show_controls = true; break; }

            case 'q':
            case 'Q': { loop = false; break; }

        }

        if (ch == '\033')    // '\033' '[' 'A'/'B'/'C'/'D' -- Up / Down / Right / Left Press
        {
            getch();
            switch(getch())
            {
    	        case 'A':
                case 'C':
                    freq += step;
                    verbose_set_frequency(dev, freq);

                    break;

    	        case 'B':
                case 'D':
                    freq -= step;
                    verbose_set_frequency(dev, freq);

                    break;
            }
        }
    }

    //------------------------------------------------------------------
    //-- Cleanup
    //------------------------------------------------------------------

    rtlsdr_close(dev);
    free (buffer);
    curs_set(true);

    endwin(); //curses done

    //finished
    std::cout << std::endl << (char)(ch) << std::endl << "Done!" << std::endl << std::endl;

    return EXIT_SUCCESS;
}
