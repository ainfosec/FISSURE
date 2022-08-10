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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "source_impl.h"
#include <gnuradio/io_signature.h>

namespace gr {
namespace limesdr {
source::sptr source::make(std::string serial, int channel_mode, const std::string& filename) {
    return gnuradio::get_initial_sptr(new source_impl(serial, channel_mode, filename));
}

source_impl::source_impl(std::string serial, int channel_mode, const std::string& filename)
    : gr::block("source",
                gr::io_signature::make(
                    0, 0, 0), // Based on channel_mode SISO/MIMO use appropriate output signature
                args_to_io_signature(channel_mode)) {
    std::cout << "---------------------------------------------------------------" << std::endl;
    std::cout << "LimeSuite Source (RX) info" << std::endl;
    std::cout << std::endl;

    // 1. Store private variables upon implementation to protect from changing them later
    stored.serial = serial;
    stored.channel_mode = channel_mode;

    if (stored.channel_mode < 0 && stored.channel_mode > 2) {
        std::cout
            << "ERROR: source_impl::source_impl(): Channel must be A(0), B(1) or (A+B) MIMO(2)"
            << std::endl;
        exit(0);
    }

    // 2. Open device if not opened
    stored.device_number = device_handler::getInstance().open_device(stored.serial);
    // 3. Check where to load settings from (file or block)
    if (!filename.empty()) {
        device_handler::getInstance().settings_from_file(stored.device_number, filename, nullptr);
        device_handler::getInstance().check_blocks(
            stored.device_number, source_block, stored.channel_mode, filename);
    } else {
        // 4. Check how many blocks were used and check values between blocks
        device_handler::getInstance().check_blocks(
            stored.device_number, source_block, stored.channel_mode, "");

        // 5. Enable required channel/s
        device_handler::getInstance().enable_channels(
            stored.device_number, stored.channel_mode, LMS_CH_RX);
    }
}

source_impl::~source_impl() {
    // Stop and destroy stream for channel 0 (if channel_mode is SISO)
    if (stored.channel_mode < 2) {
        this->release_stream(stored.device_number, &streamId[stored.channel_mode]);
    }
    // Stop and destroy stream for channels 0 & 1 (if channel_mode is MIMO)
    else if (stored.channel_mode == 2) {
        this->release_stream(stored.device_number, &streamId[LMS_CH_0]);
        this->release_stream(stored.device_number, &streamId[LMS_CH_1]);
    }
    device_handler::getInstance().close_device(stored.device_number, source_block);
}

bool source_impl::start(void) {
    std::unique_lock<std::recursive_mutex> lock(device_handler::getInstance().block_mutex);
    // Initialize and start stream for channel 0 (if channel_mode is SISO)
    if (stored.channel_mode < 2) // If SISO configure prefered channel
    {
        this->init_stream(stored.device_number, stored.channel_mode);
        if (LMS_StartStream(&streamId[stored.channel_mode]) != LMS_SUCCESS)
            device_handler::getInstance().error(stored.device_number);
    }

    // Initialize and start stream for channels 0 & 1 (if channel_mode is MIMO)
    else if (stored.channel_mode == 2) {

        this->init_stream(stored.device_number, LMS_CH_0);
        this->init_stream(stored.device_number, LMS_CH_1);

        if (LMS_StartStream(&streamId[LMS_CH_0]) != LMS_SUCCESS)
            device_handler::getInstance().error(stored.device_number);
        if (LMS_StartStream(&streamId[LMS_CH_1]) != LMS_SUCCESS)
            device_handler::getInstance().error(stored.device_number);
    }
    std::unique_lock<std::recursive_mutex> unlock(device_handler::getInstance().block_mutex);

    if (stream_analyzer) {
        t1 = std::chrono::high_resolution_clock::now();
        t2 = t1;
    }

    add_tag = true;

    return true;
}

bool source_impl::stop(void) {
    std::unique_lock<std::recursive_mutex> lock(device_handler::getInstance().block_mutex);
    // Stop stream for channel 0 (if channel_mode is SISO)
    if (stored.channel_mode < 2) {
        this->release_stream(stored.device_number, &streamId[stored.channel_mode]);
    }
    // Stop streams for channels 0 & 1 (if channel_mode is MIMO)
    else if (stored.channel_mode == 2) {
        this->release_stream(stored.device_number, &streamId[LMS_CH_0]);
        this->release_stream(stored.device_number, &streamId[LMS_CH_1]);
    }
    std::unique_lock<std::recursive_mutex> unlock(device_handler::getInstance().block_mutex);
    return true;
}

int source_impl::general_work(int noutput_items,
                              gr_vector_int& ninput_items,
                              gr_vector_const_void_star& input_items,
                              gr_vector_void_star& output_items) {
    // Receive stream for channel 0 (if channel_mode is SISO)
    if (stored.channel_mode < 2) {
        lms_stream_status_t status;
        lms_stream_meta_t rx_metadata;

        int ret0 = LMS_RecvStream(
            &streamId[stored.channel_mode], output_items[0], noutput_items, &rx_metadata, 100);
        if (ret0 < 0) {
            return 0;
        }

        LMS_GetStreamStatus(&streamId[stored.channel_mode], &status);

        if (add_tag || status.droppedPackets > 0) {
            pktLoss += status.droppedPackets;
            add_tag = false;
            this->add_time_tag(0, rx_metadata);
        }
        // Print stream stats to debug
        if (stream_analyzer == true) {
            this->print_stream_stats(status);
        }

        produce(0, ret0);
        return WORK_CALLED_PRODUCE;
    }
    // Receive stream for channels 0 & 1 (if channel_mode is MIMO)
    else if (stored.channel_mode == 2) {
        lms_stream_status_t status[2];

        lms_stream_meta_t rx_metadata[2];
        int ret0 = LMS_RecvStream(
            &streamId[LMS_CH_0], output_items[0], noutput_items, &rx_metadata[0], 100);
        int ret1 = LMS_RecvStream(
            &streamId[LMS_CH_1], output_items[1], noutput_items, &rx_metadata[1], 100);
        if (ret0 <= 0 || ret1 <= 0) {
            return 0;
        }

        LMS_GetStreamStatus(&streamId[LMS_CH_0], &status[0]);
        LMS_GetStreamStatus(&streamId[LMS_CH_1], &status[1]);

        if (add_tag || status[0].droppedPackets > 0 || status[1].droppedPackets > 0) {
            pktLoss += status[0].droppedPackets; // because every time GetStreamStatus is called,
                                                 // packet loss is reset
            add_tag = false;
            this->add_time_tag(LMS_CH_0, rx_metadata[0]);
            this->add_time_tag(LMS_CH_1, rx_metadata[1]);
        }

        // Print stream stats to debug
        if (stream_analyzer == true) {
            this->print_stream_stats(status[0]);
        }

        this->produce(0, ret0);
        this->produce(1, ret1);
        return WORK_CALLED_PRODUCE;
    }
    return 0;
}

// Setup stream
void source_impl::init_stream(int device_number, int channel) {
    streamId[channel].channel = channel;
    streamId[channel].fifoSize =
        (stored.FIFO_size == 0) ? (int)stored.samp_rate / 10 : stored.FIFO_size;
    streamId[channel].throughputVsLatency = 0.5;
    streamId[channel].isTx = LMS_CH_RX;
    streamId[channel].dataFmt = lms_stream_t::LMS_FMT_F32;

    if (LMS_SetupStream(device_handler::getInstance().get_device(stored.device_number),
                        &streamId[channel]) != LMS_SUCCESS)
        device_handler::getInstance().error(stored.device_number);

    std::cout << "INFO: source_impl::init_stream(): source channel " << channel << " (device nr. "
              << device_number << ") stream setup done." << std::endl;
}

void source_impl::release_stream(int device_number, lms_stream_t* stream) {
    if (stream->handle != 0) {
        LMS_StopStream(stream);
        LMS_DestroyStream(device_handler::getInstance().get_device(device_number), stream);
    }
}

// Print stream status
void source_impl::print_stream_stats(lms_stream_status_t status) {
    t2 = std::chrono::high_resolution_clock::now();
    auto timePeriod = std::chrono::duration_cast<std::chrono::milliseconds>(t2 - t1).count();
    if (timePeriod >= 1000) {
        std::cout << std::endl;
        std::cout << "RX";
        std::cout << "|rate: " << status.linkRate / 1e6 << " MB/s ";
        std::cout << "|dropped packets: " << pktLoss << " ";
        std::cout << "|FIFO: " << 100 * status.fifoFilledCount / status.fifoSize << "%"
                  << std::endl;
        pktLoss = 0;
        t1 = t2;
    }
}

// Add rx_time tag to stream
void source_impl::add_time_tag(int channel, lms_stream_meta_t meta) {

    uint64_t u_rate = (uint64_t)stored.samp_rate;
    double f_rate = stored.samp_rate - u_rate;
    uint64_t intpart = meta.timestamp / u_rate;
    double fracpart = (meta.timestamp - intpart * u_rate - intpart * f_rate) / stored.samp_rate;

    const pmt::pmt_t ID = pmt::string_to_symbol(stored.serial);
    const pmt::pmt_t t_val = pmt::make_tuple(pmt::from_uint64(intpart), pmt::from_double(fracpart));
    this->add_item_tag(channel, nitems_written(channel), TIME_TAG, t_val, ID);
}
// Return io_signature to manage module output count
// based on SISO (one output) and MIMO (two outputs) modes
inline gr::io_signature::sptr source_impl::args_to_io_signature(int channel_number) {
    if (channel_number < 2) {
        return gr::io_signature::make(1, 1, sizeof(gr_complex));
    } else if (channel_number == 2) {
        return gr::io_signature::make(2, 2, sizeof(gr_complex));
    } else {
        std::cout << "ERROR: source_impl::args_to_io_signature(): channel_number must be 0,1 or 2."
                  << std::endl;
        exit(0);
    }
}
double source_impl::set_center_freq(double freq, size_t chan) {
    add_tag = true;
    return device_handler::getInstance().set_rf_freq(
        stored.device_number, LMS_CH_RX, LMS_CH_0, freq);
}

void source_impl::set_nco(float nco_freq, int channel) {
    device_handler::getInstance().set_nco(stored.device_number, LMS_CH_RX, channel, nco_freq);
    add_tag = true;
}

void source_impl::set_antenna(int antenna, int channel) {
    device_handler::getInstance().set_antenna(stored.device_number, channel, LMS_CH_RX, antenna);
}

double source_impl::set_bandwidth(double analog_bandw, int channel) {
    add_tag = true;
    return device_handler::getInstance().set_analog_filter(
        stored.device_number, LMS_CH_RX, channel, analog_bandw);
}

void source_impl::set_digital_filter(double digital_bandw, int channel) {
    device_handler::getInstance().set_digital_filter(
        stored.device_number, LMS_CH_RX, channel, digital_bandw);
    add_tag = true;
}

unsigned source_impl::set_gain(unsigned gain_dB, int channel) {
    return device_handler::getInstance().set_gain(
        stored.device_number, LMS_CH_RX, channel, gain_dB);
}

void source_impl::calibrate(double bandw, int channel) {
    device_handler::getInstance().calibrate(stored.device_number, LMS_CH_RX, channel, bandw);
}

double source_impl::set_sample_rate(double rate) {
    device_handler::getInstance().set_samp_rate(stored.device_number, rate);
    stored.samp_rate = rate;
    return rate;
}

void source_impl::set_buffer_size(uint32_t size) { stored.FIFO_size = size; }

void source_impl::set_oversampling(int oversample) {
    device_handler::getInstance().set_oversampling(stored.device_number, oversample);
}

void source_impl::set_tcxo_dac(uint16_t dacVal) {
    device_handler::getInstance().set_tcxo_dac(stored.device_number, dacVal);
}

} // namespace limesdr
} // namespace gr
