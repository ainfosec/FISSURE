/* -*- c++ -*- */
/*
 * Copyright 2017 Clayton Smith.
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "hdc_encoder_impl.h"
#include <gnuradio/io_signature.h>

namespace gr {
namespace nrsc5 {

hdc_encoder::sptr hdc_encoder::make(int channels, int bitrate)
{
    return gnuradio::get_initial_sptr(new hdc_encoder_impl(channels, bitrate));
}


/*
 * The private constructor
 */
hdc_encoder_impl::hdc_encoder_impl(int channels, int bitrate)
    : gr::block("hdc_encoder",
                gr::io_signature::make(1, 2, sizeof(float)),
                gr::io_signature::make(1, 1, sizeof(unsigned char)))
{
    this->channels = channels;
    bytes_per_frame = bitrate * SAMPLES_PER_FRAME / HDC_SAMPLE_RATE / 8;
    set_relative_rate((double)bytes_per_frame / SAMPLES_PER_FRAME);

    int vbr = 0;
    int afterburner = 1;
    CHANNEL_MODE mode;
    AACENC_InfoStruct info = { 0 };
    switch (channels) {
    case 1:
        mode = MODE_1;
        break;
    case 2:
        mode = MODE_2;
        break;
    default:
        throw std::runtime_error("hdc_encoder: channels must be 1 or 2");
    }
    if (aacEncOpen(&handle, 0, channels) != AACENC_OK) {
        throw std::runtime_error("hdc_encoder: Unable to open decoder");
    }
    if (aacEncoder_SetParam(handle, AACENC_AOT, AOT_HDC) != AACENC_OK) {
        throw std::runtime_error("hdc_encoder: Unable to set the AOT");
    }
    if (aacEncoder_SetParam(handle, AACENC_SAMPLERATE, HDC_SAMPLE_RATE) != AACENC_OK) {
        throw std::runtime_error("hdc_encoder: Unable to set the sample rate");
    }
    if (aacEncoder_SetParam(handle, AACENC_CHANNELMODE, mode) != AACENC_OK) {
        throw std::runtime_error("hdc_encoder: Unable to set the channel mode");
    }
    if (aacEncoder_SetParam(handle, AACENC_CHANNELORDER, 1) != AACENC_OK) {
        throw std::runtime_error("hdc_encoder: Unable to set the channel order");
    }
    if (vbr) {
        if (aacEncoder_SetParam(handle, AACENC_BITRATEMODE, vbr) != AACENC_OK) {
            throw std::runtime_error("hdc_encoder: Unable to set the VBR bitrate mode");
        }
    } else {
        if (aacEncoder_SetParam(handle, AACENC_BITRATE, bitrate) != AACENC_OK) {
            throw std::runtime_error("hdc_encoder: Unable to set the bitrate");
        }
    }
    if (aacEncoder_SetParam(handle, AACENC_TRANSMUX, 2) != AACENC_OK) {
        throw std::runtime_error("hdc_encoder: Unable to set the ADTS transmux");
    }
    if (aacEncoder_SetParam(handle, AACENC_AFTERBURNER, afterburner) != AACENC_OK) {
        throw std::runtime_error("hdc_encoder: Unable to set the afterburner mode");
    }
    if (aacEncEncode(handle, NULL, NULL, NULL, NULL) != AACENC_OK) {
        throw std::runtime_error("hdc_encoder: Unable to initialize the encoder");
    }
    if (aacEncInfo(handle, &info) != AACENC_OK) {
        throw std::runtime_error("hdc_encoder: Unable to get the encoder info");
    }

    frame_length = info.frameLength;
    max_out_buf_bytes = info.maxOutBufBytes;
    convert_buf = (short*)malloc(channels * sizeof(short) * frame_length);
    outbuf = (unsigned char*)malloc(max_out_buf_bytes);
    outbuf_off = 0;
    outbuf_len = 0;
}

/*
 * Our virtual destructor.
 */
hdc_encoder_impl::~hdc_encoder_impl()
{
    aacEncClose(&handle);
    free(convert_buf);
    free(outbuf);
}

void hdc_encoder_impl::forecast(int noutput_items, gr_vector_int& ninput_items_required)
{
    for (int channel = 0; channel < channels; channel++) {
        if (noutput_items <= outbuf_len) {
            ninput_items_required[channel] = 0;
        } else {
            ninput_items_required[channel] =
                (((noutput_items - outbuf_len) / bytes_per_frame) + 1) *
                SAMPLES_PER_FRAME;
        }
    }
}

int hdc_encoder_impl::general_work(int noutput_items,
                                   gr_vector_int& ninput_items,
                                   gr_vector_const_void_star& input_items,
                                   gr_vector_void_star& output_items)
{
    const float** in = (const float**)&input_items[0];
    unsigned char* out = (unsigned char*)output_items[0];

    int in_off = 0;
    int out_off = 0;

    int min_input_items = INT_MAX;
    for (int channel = 0; channel < channels; channel++) {
        if (ninput_items[channel] < min_input_items) {
            min_input_items = ninput_items[channel];
        }
    }

    while (out_off < noutput_items) {
        if (out_off + outbuf_len > noutput_items) {
            int space = noutput_items - out_off;
            memcpy(out + out_off, outbuf + outbuf_off, space);
            out_off += space;
            outbuf_off += space;
            outbuf_len -= space;
            break;
        }

        memcpy(out + out_off, outbuf + outbuf_off, outbuf_len);
        out_off += outbuf_len;
        outbuf_off = 0;
        outbuf_len = 0;

        if (in_off + frame_length > min_input_items)
            break;

        AACENC_BufDesc in_buf = { 0 }, out_buf = { 0 };
        AACENC_InArgs in_args = { 0 };
        AACENC_OutArgs out_args = { 0 };
        int in_identifier = IN_AUDIO_DATA;
        int in_size, in_elem_size;
        int out_identifier = OUT_BITSTREAM_DATA;
        int out_size, out_elem_size;
        void *in_ptr, *out_ptr;
        AACENC_ERROR err;

        int convert_off = 0;
        for (int i = 0; i < frame_length; i++) {
            for (int channel = 0; channel < channels; channel++) {
                convert_buf[convert_off++] = (short)(in[channel][in_off] * 32768);
            }
            in_off++;
        }

        in_ptr = convert_buf;
        in_size = channels * sizeof(short) * frame_length;
        in_elem_size = sizeof(short);

        in_args.numInSamples = channels * frame_length;
        in_buf.numBufs = 1;
        in_buf.bufs = &in_ptr;
        in_buf.bufferIdentifiers = &in_identifier;
        in_buf.bufSizes = &in_size;
        in_buf.bufElSizes = &in_elem_size;

        out_ptr = outbuf;
        out_size = max_out_buf_bytes;
        out_elem_size = 1;
        out_buf.numBufs = 1;
        out_buf.bufs = &out_ptr;
        out_buf.bufferIdentifiers = &out_identifier;
        out_buf.bufSizes = &out_size;
        out_buf.bufElSizes = &out_elem_size;

        if ((err = aacEncEncode(handle, &in_buf, &out_buf, &in_args, &out_args)) !=
            AACENC_OK) {
            throw std::runtime_error("hdc_encoder: Encoding failed");
        }
        outbuf_len = out_args.numOutBytes;
    }

    consume_each(in_off);
    return out_off;
}

} /* namespace nrsc5 */
} /* namespace gr */
