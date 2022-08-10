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

#include "sink_impl.h"
#include <gnuradio/io_signature.h>

namespace gr {
namespace limesdr {
sink::sptr sink::make(std::string serial,
                      int channel_mode,
                      const std::string& filename,
                      const std::string& length_tag_name) {
    return gnuradio::get_initial_sptr(
        new sink_impl(serial, channel_mode, filename, length_tag_name));
}

sink_impl::sink_impl(std::string serial,
                     int channel_mode,
                     const std::string& filename,
                     const std::string& length_tag_name)
    : gr::block(
          "sink",
          args_to_io_signature(
              channel_mode), // Based on channel_mode SISO/MIMO use appropriate input signature
          gr::io_signature::make(0, 0, 0)) {
    std::cout << "---------------------------------------------------------------" << std::endl;
    std::cout << "LimeSuite Sink (TX) info" << std::endl;
    std::cout << std::endl;

    LENGTH_TAG = length_tag_name.empty() ? pmt::PMT_NIL : pmt::string_to_symbol(length_tag_name);
    // 1. Store private variables upon implementation to protect from changing them later
    stored.serial = serial;
    stored.channel_mode = channel_mode;

    if (stored.channel_mode < 0 && stored.channel_mode > 2) {
        std::cout << "ERROR: sink_impl::sink_impl(): Channel must be A(1), B(2) or (A+B) MIMO(3)"
                  << std::endl;
        exit(0);
    }

    // 2. Open device if not opened
    stored.device_number = device_handler::getInstance().open_device(stored.serial);
    // 3. Check where to load settings from (file or block)
    if (!filename.empty()) {
        device_handler::getInstance().settings_from_file(stored.device_number, filename, pa_path);
        device_handler::getInstance().check_blocks(
            stored.device_number, sink_block, stored.channel_mode, filename);
    } else {
        // 4. Check how many blocks were used and check values between blocks
        device_handler::getInstance().check_blocks(
            stored.device_number, sink_block, stored.channel_mode, "");

        // 5. Enable required channels
        device_handler::getInstance().enable_channels(
            stored.device_number, stored.channel_mode, LMS_CH_TX);

        // 6. Disable PA path
        this->toggle_pa_path(stored.device_number, false);
    }
}

sink_impl::~sink_impl() {
    // Stop and destroy stream for channel 0 (if channel_mode is SISO)
    if (stored.channel_mode < 2) {
        this->release_stream(stored.device_number, &streamId[stored.channel_mode]);
    }
    // Stop and destroy stream for channels 0 & 1 (if channel_mode is MIMO)
    else if (stored.channel_mode == 2) {
        this->release_stream(stored.device_number, &streamId[LMS_CH_0]);
        this->release_stream(stored.device_number, &streamId[LMS_CH_1]);
    }
    device_handler::getInstance().close_device(stored.device_number, sink_block);
}

bool sink_impl::start(void) {
    std::unique_lock<std::recursive_mutex> lock(device_handler::getInstance().block_mutex);
    // Init timestamp
    tx_meta.timestamp = 0;

    if (stream_analyzer) {
        t1 = std::chrono::high_resolution_clock::now();
        t2 = t1;
    }
    // Enable PA path
    this->toggle_pa_path(stored.device_number, true);
    // Initialize and start stream for channel 0 (if channel_mode is SISO)
    if (stored.channel_mode < 2) // If SISO configure prefered channel
    {
        this->init_stream(stored.device_number, stored.channel_mode);
        LMS_StartStream(&streamId[stored.channel_mode]);
    }
    // Initialize and start stream for channels 0 & 1 (if channel_mode is MIMO)
    else if (stored.channel_mode == 2) {
        this->init_stream(stored.device_number, LMS_CH_0);
        this->init_stream(stored.device_number, LMS_CH_1);

        LMS_StartStream(&streamId[LMS_CH_0]);
        LMS_StartStream(&streamId[LMS_CH_1]);
    }
    std::unique_lock<std::recursive_mutex> unlock(device_handler::getInstance().block_mutex);
    return true;
}

bool sink_impl::stop(void) {
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
    // Disable PA path
    this->toggle_pa_path(stored.device_number, false);
    std::unique_lock<std::recursive_mutex> unlock(device_handler::getInstance().block_mutex);
    return true;
}

int sink_impl::general_work(int noutput_items,
                            gr_vector_int& ninput_items,
                            gr_vector_const_void_star& input_items,
                            gr_vector_void_star& output_items) {
    // Init number of items to be sent and timestamps
    nitems_send = noutput_items;
    int current_sample = nitems_read(0);
    tx_meta.waitForTimestamp = false;
    tx_meta.flushPartialPacket = false;
    // Check if channel 0 has any tags
    this->work_tags(noutput_items);
    // If length tag has been found burst_length should be higher than 0
    if (burst_length > 0) {
        nitems_send = std::min<long>(burst_length, nitems_send);
        // Make sure to wait for timestamp
        tx_meta.waitForTimestamp = true;
        // Check if it is the end of the burst
        if (burst_length - (long)nitems_send == 0) {
            tx_meta.flushPartialPacket = true;
        }
    }

    // Send stream for channel 0 (if channel_mode is SISO)
    if (stored.channel_mode < 2) {
        // Print stream stats to debug
        if (stream_analyzer == true) {
            this->print_stream_stats(stored.channel_mode);
        }
        ret[0] = LMS_SendStream(
            &streamId[stored.channel_mode], input_items[0], nitems_send, &tx_meta, 100);
        if (ret[0] < 0) {
            return 0;
        }
        burst_length -= ret[0];
        tx_meta.timestamp += ret[0];
        consume(0, ret[0]);
    }
    // Send stream for channels 0 & 1 (if channel_mode is MIMO)
    else if (stored.channel_mode == 2) {
        // Print stream stats to debug
        if (stream_analyzer == true) {
            this->print_stream_stats(LMS_CH_0);
        }
        ret[0] = LMS_SendStream(&streamId[LMS_CH_0], input_items[0], nitems_send, &tx_meta, 100);
        ret[1] = LMS_SendStream(&streamId[LMS_CH_1], input_items[1], nitems_send, &tx_meta, 100);
        // Send data
        if (ret[0] < 0 || ret[1] < 0) {
            return 0;
        }
        burst_length -= ret[0];
        tx_meta.timestamp += ret[0];
        consume(0, ret[0]);
        consume(1, ret[1]);
    }
    return 0;
}
void sink_impl::work_tags(int noutput_items) {
    std::vector<tag_t> tags;
    int current_sample = nitems_read(0);
    get_tags_in_range(tags, 0, current_sample, current_sample + noutput_items);

    if (!tags.empty()) {
        std::sort(tags.begin(), tags.end(), tag_t::offset_compare);
        // Go through the tags
        for (tag_t cTag : tags) {
            // Found tx_time tag
            if (pmt::eq(cTag.key, TIME_TAG)) {
                // Convert time to sample timestamp
                uint64_t secs = pmt::to_uint64(pmt::tuple_ref(cTag.value, 0));
                double fracs = pmt::to_double(pmt::tuple_ref(cTag.value, 1));
                uint64_t u_rate = (uint64_t)stored.samp_rate;
                double f_rate = stored.samp_rate - u_rate;
                uint64_t timestamp =
                    u_rate * secs + llround(secs * f_rate + fracs * stored.samp_rate);

                if (cTag.offset == current_sample) {
                    tx_meta.waitForTimestamp = true;
                    tx_meta.timestamp = timestamp;
                } else {
                    nitems_send = cTag.offset - current_sample;
                    break;
                }
            }
            // Found length tag
            else if (!pmt::is_null(LENGTH_TAG) && pmt::eq(cTag.key, LENGTH_TAG)) {
                if (cTag.offset == current_sample) {
                    // Found length tag in the middle of the burst
                    if (burst_length > 0 && ret[0] > 0)
                        std::cout << "Warning: Length tag has been preemted" << std::endl;
                    burst_length = pmt::to_long(cTag.value);
                } else {
                    nitems_send = cTag.offset - current_sample;
                    break;
                }
            }
        }
    }
}
// Print stream status
void sink_impl::print_stream_stats(int channel) {
    t2 = std::chrono::high_resolution_clock::now();
    auto timePeriod = std::chrono::duration_cast<std::chrono::milliseconds>(t2 - t1).count();
    if (timePeriod >= 1000) {
        lms_stream_status_t status;
        LMS_GetStreamStatus(&streamId[channel], &status);
        std::cout << std::endl;
        std::cout << "TX";
        std::cout << "|rate: " << status.linkRate / 1e6 << " MB/s ";
        std::cout << "|dropped packets: " << status.droppedPackets << " ";
        std::cout << "|FIFO: " << 100 * status.fifoFilledCount / status.fifoSize << "%"
                  << std::endl;
        t1 = t2;
    }
}
// Setup stream
void sink_impl::init_stream(int device_number, int channel) {
    streamId[channel].channel = channel;
    streamId[channel].fifoSize =
        (stored.FIFO_size == 0) ? (int)stored.samp_rate / 10 : stored.FIFO_size;
    streamId[channel].throughputVsLatency = 0.5;
    streamId[channel].isTx = LMS_CH_TX;
    streamId[channel].dataFmt = lms_stream_t::LMS_FMT_F32;

    if (LMS_SetupStream(device_handler::getInstance().get_device(device_number),
                        &streamId[channel]) != LMS_SUCCESS)
        device_handler::getInstance().error(device_number);

    std::cout << "INFO: sink_impl::init_stream(): sink channel " << channel << " (device nr. "
              << device_number << ") stream setup done." << std::endl;
}

void sink_impl::release_stream(int device_number, lms_stream_t* stream) {
    if (stream->handle != 0) {
        LMS_StopStream(stream);
        LMS_DestroyStream(device_handler::getInstance().get_device(device_number), stream);
    }
}

// Return io_signature to manage module input count
// based on SISO (one input) and MIMO (two inputs) modes
inline gr::io_signature::sptr sink_impl::args_to_io_signature(int channel_number) {
    if (channel_number < 2) {
        return gr::io_signature::make(1, 1, sizeof(gr_complex));
    } else if (channel_number == 2) {
        return gr::io_signature::make(2, 2, sizeof(gr_complex));
    } else {
        std::cout << "ERROR: sink_impl::args_to_io_signature(): channel_number must be 0,1 or 2."
                  << std::endl;
        exit(0);
    }
}

double sink_impl::set_center_freq(double freq, size_t chan) {
    return device_handler::getInstance().set_rf_freq(
        stored.device_number, LMS_CH_TX, LMS_CH_0, freq);
}

void sink_impl::set_antenna(int antenna, int channel) {
    pa_path[channel] = antenna;
    device_handler::getInstance().set_antenna(stored.device_number, channel, LMS_CH_TX, antenna);
}

void sink_impl::toggle_pa_path(int device_number, bool enable) {
    LMS_RegisterLogHandler([](int, const char*) {});
    if (stored.channel_mode < 2) {
        LMS_SetAntenna(device_handler::getInstance().get_device(device_number),
                       LMS_CH_TX,
                       stored.channel_mode,
                       enable ? pa_path[stored.channel_mode] : 0);
    } else {
        LMS_SetAntenna(device_handler::getInstance().get_device(device_number),
                       LMS_CH_TX,
                       LMS_CH_0,
                       enable ? pa_path[0] : 0);
        LMS_SetAntenna(device_handler::getInstance().get_device(device_number),
                       LMS_CH_TX,
                       LMS_CH_1,
                       enable ? pa_path[1] : 0);
    }
    LMS_RegisterLogHandler(nullptr);
}

void sink_impl::set_nco(float nco_freq, int channel) {
    device_handler::getInstance().set_nco(stored.device_number, LMS_CH_TX, channel, nco_freq);
}

double sink_impl::set_bandwidth(double analog_bandw, int channel) {
    return device_handler::getInstance().set_analog_filter(
        stored.device_number, LMS_CH_TX, channel, analog_bandw);
}

void sink_impl::set_digital_filter(double digital_bandw, int channel) {
    device_handler::getInstance().set_digital_filter(
        stored.device_number, LMS_CH_TX, channel, digital_bandw);
}

unsigned sink_impl::set_gain(unsigned gain_dB, int channel) {
    return device_handler::getInstance().set_gain(
        stored.device_number, LMS_CH_TX, channel, gain_dB);
}
void sink_impl::calibrate(double bandw, int channel) {
    // PA path needs to be enabled for calibration
    this->toggle_pa_path(stored.device_number, true);
    device_handler::getInstance().calibrate(stored.device_number, LMS_CH_TX, channel, bandw);
    this->toggle_pa_path(stored.device_number, false);
}

double sink_impl::set_sample_rate(double rate) {
    device_handler::getInstance().set_samp_rate(stored.device_number, rate);
    stored.samp_rate = rate;
    return rate;
}

void sink_impl::set_buffer_size(uint32_t size) { stored.FIFO_size = size; }

void sink_impl::set_oversampling(int oversample) {
    device_handler::getInstance().set_oversampling(stored.device_number, oversample);
}

void sink_impl::set_tcxo_dac(uint16_t dacVal) {
    device_handler::getInstance().set_tcxo_dac(stored.device_number, dacVal);
}

} // namespace limesdr
} // namespace gr
