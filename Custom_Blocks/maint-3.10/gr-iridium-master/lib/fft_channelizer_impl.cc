/* -*- c++ -*- */
/*
 * Copyright 2022 gr-iridium author.
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Many of this is following directly what is presented
 * here: https://media.ccc.de/v/gpn18-15-channelizing-with-gnuradio
 *
 * No special windowing is performed. This leads to a lot of noise
 * in the output. First tests indicate no significant drop in
 * overall performance though.
 */

#include "fft_channelizer_impl.h"
#include <gnuradio/io_signature.h>

#include <chrono>
#include <thread>

namespace gr {
namespace iridium {

constexpr bool is_powerof2(int v) { return v && ((v & (v - 1)) == 0); }

using input_type = gr_complex;
using output_type = gr_complex;
fft_channelizer::sptr fft_channelizer::make(int fft_size,
                                            int decimation,
                                            bool activate_streams,
                                            int pdu_ports,
                                            int max_burst_size,
                                            int outstanding_limit,
                                            bool drop_overflow)
{
    return gnuradio::make_block_sptr<fft_channelizer_impl>(fft_size,
                                                           decimation,
                                                           activate_streams,
                                                           pdu_ports,
                                                           max_burst_size,
                                                           outstanding_limit,
                                                           drop_overflow);
}


/*
 * The private constructor
 */
fft_channelizer_impl::fft_channelizer_impl(int fft_size,
                                           int decimation,
                                           bool activate_streams,
                                           int pdu_ports,
                                           int max_burst_size,
                                           int outstanding_limit,
                                           bool drop_overflow)
    : gr::sync_decimator(
          "fft_channelizer",
          gr::io_signature::make(
              1 /* min inputs */, 1 /* max inputs */, sizeof(input_type)),
          gr::io_signature::make(activate_streams ? decimation + 1 : 0 /* min outputs */,
                                 activate_streams ? decimation + 1 : 0 /* max outputs */,
                                 sizeof(output_type)),
          decimation),
      d_decimation(decimation),
      d_fft_size(fft_size),
      d_ifft_size(fft_size / decimation),
      d_fft(fft_size, 1),
      d_ifft(fft_size / decimation, 1),
      d_inverse_overlap(4),
      d_output_step((fft_size - fft_size / decimation) / decimation),
      d_channels(decimation + 1),
      d_channel_active(0),
      d_pdu_ports(pdu_ports),
      d_max_burst_size(max_burst_size),
      d_bursts(decimation + 1),
      d_outstanding_limit(outstanding_limit),
      d_drop_overflow(drop_overflow),
      d_max_outstanding(0),
      d_outstanding(0),
      d_n_dropped_bursts(0),
      d_next_pdu_port(0)
{
    // FFT size and decimation must be a power of two so the output sizes are
    // also a power of two.
    if (!is_powerof2(d_fft_size)) {
        throw std::runtime_error("FFT size must be a power of two");
    }

    if (!is_powerof2(d_decimation)) {
        throw std::runtime_error("Decimation must be a power of two");
    }

    // Make sure the output channels are aligned to integer bins of the input FFT.
    // E.g. fft size of 1024 and decimation of 16 work, but decimation of 32 does not.
    if ((d_fft_size - d_ifft_size) % d_decimation != 0) {
        throw std::runtime_error("FFT size and decimation can not be matched.");
    }

    // Make sure we don't have phase shifts between two iterations.
    if (d_output_step % d_inverse_overlap != 0) {
        throw std::runtime_error("FFT size and decimation can not be matched.");
    }

    set_output_multiple(d_ifft_size - d_ifft_size / d_inverse_overlap);

    // We want to keep the last 1/d_inverse_overlap block in the history buffer
    set_history(d_fft_size / d_inverse_overlap + 1);

    if (pdu_ports > 0) {
        for (int i = 0; i < pdu_ports; i++) {
            auto port_name = pmt::mp("cpdus" + std::to_string(i));
            message_port_register_out(port_name);
        }

        message_port_register_in(pmt::mp("burst_handled"));
        set_msg_handler(pmt::mp("burst_handled"),
                        [this](pmt::pmt_t msg) { this->burst_handled(msg); });
    }

    d_out = (fftwf_complex*)volk_malloc(d_fft_size * sizeof(fftwf_complex),
                                        volk_get_alignment());
}

/*
 * Our virtual destructor.
 */
fft_channelizer_impl::~fft_channelizer_impl() {}

void fft_channelizer_impl::burst_handled(pmt::pmt_t msg) { d_outstanding--; }

uint64_t fft_channelizer_impl::get_n_dropped_bursts() { return d_n_dropped_bursts; }

int fft_channelizer_impl::get_output_queue_size() { return d_outstanding; }

int fft_channelizer_impl::get_output_max_queue_size()
{
    int tmp = d_max_outstanding;
    d_max_outstanding = 0;
    return tmp;
}

int fft_shift(int N, int f)
{
    if (f < N / 2) {
        return f + N / 2;
    } else {
        return f - N / 2;
    }
}

int positive_offset(int N, int step, int channel, int n)
{
    return fft_shift(N, channel * step + n / 2);
}

int negative_offset(int N, int step, int channel, int n)
{
    return fft_shift(N, channel * step);
}

float fft_channelizer_impl::channel_center(int channel)
{
    float channel_width = 1. / d_decimation;
    return channel_width / 2 + channel * (float)d_output_step / d_fft_size - 0.5;
}

float fft_channelizer_impl::channel_lower_border(int channel)
{
    float channel_width = 1. / d_decimation;
    return channel_center(channel) - channel_width / 2;
}

float fft_channelizer_impl::channel_upper_border(int channel)
{
    float channel_width = 1. / d_decimation;
    return channel_center(channel) + channel_width / 2;
}

uint64_t fft_channelizer_impl::activated_channels(tag_t& new_burst)
{
    uint64_t ret = 0;
    float relative_frequency = pmt::to_float(
        pmt::dict_ref(new_burst.value, pmt::mp("relative_frequency"), pmt::PMT_NIL));

    for (int i = 0; i < d_channels; i++) {
        if (channel_lower_border(i) < relative_frequency &&
            relative_frequency < channel_upper_border(i)) {
            ret |= (1 << i);
        }
    }
    return ret;
}

burst_data fft_channelizer_impl::create_burst(tag_t& new_burst, int channel)
{
    uint64_t id =
        pmt::to_uint64(pmt::dict_ref(new_burst.value, pmt::mp("id"), pmt::PMT_NIL));
    float magnitude =
        pmt::to_float(pmt::dict_ref(new_burst.value, pmt::mp("magnitude"), pmt::PMT_NIL));
    double center_frequency = pmt::to_double(
        pmt::dict_ref(new_burst.value, pmt::mp("center_frequency"), pmt::PMT_NIL));
    float sample_rate = pmt::to_float(
        pmt::dict_ref(new_burst.value, pmt::mp("sample_rate"), pmt::PMT_NIL));
    float relative_frequency = pmt::to_float(
        pmt::dict_ref(new_burst.value, pmt::mp("relative_frequency"), pmt::PMT_NIL));
    uint64_t timestamp = pmt::to_uint64(
        pmt::dict_ref(new_burst.value, pmt::mp("timestamp"), pmt::PMT_NIL));
    float noise =
        pmt::to_float(pmt::dict_ref(new_burst.value, pmt::mp("noise"), pmt::PMT_NIL));

    // Adjust the values based on our position behind a potential filter bank
    center_frequency += channel_center(channel) * sample_rate;
    sample_rate = sample_rate / d_decimation;
    relative_frequency = (relative_frequency - channel_center(channel)) * d_decimation;

    burst_data burst = { id,
                         (double)new_burst.offset / d_decimation,
                         magnitude,
                         relative_frequency,
                         center_frequency,
                         sample_rate,
                         timestamp,
                         noise,
                         0 };
    burst.data = (gr_complex*)malloc(sizeof(gr_complex) * d_max_burst_size);
    return burst;
}

void fft_channelizer_impl::append_to_burst(burst_data& burst,
                                           const gr_complex* data,
                                           size_t n)
{
    // If the burst really gets longer than this, we can just throw away the data
    if (burst.len + n <= d_max_burst_size) {
        memcpy(burst.data + burst.len, data, n * sizeof(gr_complex));
        burst.len += n;
    }
}

void fft_channelizer_impl::publish_burst(burst_data& burst)
{
    if (d_outstanding >= d_outstanding_limit && d_drop_overflow) {
        d_n_dropped_bursts++;
        return;
    }

    pmt::pmt_t d_pdu_meta = pmt::make_dict();
    pmt::pmt_t d_pdu_vector = pmt::init_c32vector(burst.len, burst.data);

    d_pdu_meta = pmt::dict_add(d_pdu_meta, pmt::mp("id"), pmt::mp(burst.id));
    d_pdu_meta =
        pmt::dict_add(d_pdu_meta, pmt::mp("magnitude"), pmt::mp(burst.magnitude));
    d_pdu_meta = pmt::dict_add(
        d_pdu_meta, pmt::mp("relative_frequency"), pmt::mp(burst.relative_frequency));
    d_pdu_meta = pmt::dict_add(
        d_pdu_meta, pmt::mp("center_frequency"), pmt::mp(burst.center_frequency));
    d_pdu_meta =
        pmt::dict_add(d_pdu_meta, pmt::mp("sample_rate"), pmt::mp(burst.sample_rate));
    d_pdu_meta =
        pmt::dict_add(d_pdu_meta, pmt::mp("timestamp"), pmt::mp(burst.timestamp));
    d_pdu_meta = pmt::dict_add(d_pdu_meta, pmt::mp("noise"), pmt::mp(burst.noise));

    pmt::pmt_t msg = pmt::cons(d_pdu_meta, d_pdu_vector);
    message_port_pub(pmt::mp("cpdus" + std::to_string(d_next_pdu_port)), msg);

    d_next_pdu_port = (d_next_pdu_port + 1) % d_pdu_ports;

    d_outstanding++;
    if (d_outstanding > d_max_outstanding) {
        d_max_outstanding = d_outstanding;
    }
}


int fft_channelizer_impl::work(int noutput_items,
                               gr_vector_const_void_star& input_items,
                               gr_vector_void_star& output_items)
{
    const input_type* in = reinterpret_cast<const input_type*>(input_items[0]);

    int ninput_items = noutput_items * d_decimation;

    if (d_outstanding >= d_outstanding_limit && !d_drop_overflow) {
        // We need to wait a bit until our queue is not full anymore
        std::this_thread::sleep_for(std::chrono::microseconds(100000));

        // Tell the scheduler that we have not consumed any input
        return 0;
    }

    // GNURadio supplies us with some history in the front of the buffer. We use
    // this for the overlap of the FFT.
    for (int i = 0; i < ninput_items; i += d_fft_size - d_fft_size / d_inverse_overlap) {
        std::vector<tag_t> new_bursts;

        // TODO: there are two options here and one is correct...
        get_tags_in_window(new_bursts,
                           0,
                           i,
                           i + d_fft_size - d_fft_size / d_inverse_overlap,
                           pmt::mp("new_burst"));

        // No stream outputs, no channel active, no new channel becoming active => No need
        // to generate any output
        if (output_items.size() == 0 && d_channel_active == 0 && new_bursts.size() == 0) {
            continue;
        }
        // Initial forward FFT. No window is applied.
#if 0
        fftwf_complex * fft_in = (fftwf_complex*)&in[i];
        auto it = d_fft_plans.find(fft_in);

        if(it == d_fft_plans.end()) {
            fftwf_plan plan = fftwf_plan_dft_1d(d_fft_size, fft_in, d_out, FFTW_FORWARD, FFTW_MEASURE);
            d_fft_plans.insert({fft_in, plan});
            fftwf_execute(plan);
        } else {
            fftwf_execute(it->second);
        }
#else
        memcpy(d_fft.get_inbuf(), &in[i], d_fft_size * sizeof(gr_complex));
        d_fft.execute();
#endif


        for (tag_t new_burst : new_bursts) {
            d_channel_active |= activated_channels(new_burst);
        }

        std::vector<tag_t> gone_bursts;
        get_tags_in_window(gone_bursts,
                           0,
                           i,
                           i + d_fft_size - d_fft_size / d_inverse_overlap,
                           pmt::mp("gone_burst"));

        // Cycle through each output and perform the smaller reverse FFT at the
        // appropriate location of the larger forward FFTs output.
        for (int j = 0; j < d_channels; j++) {

            if (output_items.size() > 0 || d_channel_active & (1 << j)) {
                // Construct the input to the reverse FFT. We need to copy the two halves
                // as the output of the initial FFT still is [DC, Positive Freq, Negative
                // Freq].
                volk_32fc_s32fc_multiply_32fc(
                    &d_ifft.get_inbuf()[0],
                    &d_fft.get_outbuf()[positive_offset(
                        d_fft_size, d_output_step, j, d_ifft_size)],
                    1. / d_fft_size,
                    d_ifft_size / 2);
                volk_32fc_s32fc_multiply_32fc(
                    &d_ifft.get_inbuf()[d_ifft_size / 2],
                    &d_fft.get_outbuf()[negative_offset(
                        d_fft_size, d_output_step, j, d_ifft_size)],
                    1. / d_fft_size,
                    d_ifft_size / 2);
                d_ifft.execute();

                if (output_items.size() > 0) {
                    output_type* out = reinterpret_cast<output_type*>(output_items[j]);
                    memcpy(&out[i / d_decimation],
                           &d_ifft.get_outbuf()[d_ifft_size / d_inverse_overlap],
                           (d_ifft_size - d_ifft_size / d_inverse_overlap) *
                               sizeof(gr_complex));
                }

                if (d_pdu_ports > 0) {
                    // Fill already active bursts with samples
                    for (auto& kv : d_bursts[j]) {
                        append_to_burst(
                            kv.second,
                            &d_ifft.get_outbuf()[d_ifft_size / d_inverse_overlap],
                            (d_ifft_size - d_ifft_size / d_inverse_overlap));
                    }

                    // Create new bursts. As new new bursts might start in the middle of
                    // this block, the already active bursts get their data before
                    // creating the new ones.
                    for (tag_t new_burst : new_bursts) {
                        if (activated_channels(new_burst) & (1 << j)) {
                            burst_data burst = create_burst(new_burst, j);
                            d_bursts[j][burst.id] = burst;
                            int max_items = d_ifft_size - d_ifft_size / d_inverse_overlap;
                            int relative_offset =
                                (new_burst.offset - nitems_read(0) - i) / d_decimation;
                            int to_copy = max_items - relative_offset;
                            append_to_burst(
                                d_bursts[j][burst.id],
                                &d_ifft.get_outbuf()[d_ifft_size / d_inverse_overlap +
                                                     relative_offset],
                                to_copy);
                        }
                    }


                    // Publish gone bursts
                    for (tag_t tag : gone_bursts) {
                        uint64_t id = pmt::to_uint64(
                            pmt::dict_ref(tag.value, pmt::mp("id"), pmt::PMT_NIL));

                        if (d_bursts[j].count(id)) {
                            burst_data& burst = d_bursts[j][id];
                            publish_burst(burst);
                            free(d_bursts[j][id].data);
                            d_bursts[j].erase(id);
                        }
                    }

                    if (d_bursts[j].size() == 0) {
                        d_channel_active &= ~(1 << j);
                    }
                }
            }
        }
    }

    // Tell runtime system how many output items we produced.
    return noutput_items;
}

} /* namespace iridium */
} /* namespace gr */
