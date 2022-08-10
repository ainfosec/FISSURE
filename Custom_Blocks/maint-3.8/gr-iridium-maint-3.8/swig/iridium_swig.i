/* -*- c++ -*- */

#define IRIDIUM_API

%include "gnuradio.i"           // the common stuff

//load generated python docstrings
%include "iridium_swig_doc.i"

%{
#include "iridium/fft_burst_tagger.h"
#include "iridium/iuchar_to_complex.h"
#include "iridium/tagged_burst_to_pdu.h"
#include "iridium/burst_downmix.h"
#include "iridium/pdu_null_sink.h"
#include "iridium/iridium_qpsk_demod_cpp.h"
#include "iridium/pdu_round_robin.h"
%}

%include "iridium/fft_burst_tagger.h"
GR_SWIG_BLOCK_MAGIC2(iridium, fft_burst_tagger);
%include "iridium/iuchar_to_complex.h"
GR_SWIG_BLOCK_MAGIC2(iridium, iuchar_to_complex);
%include "iridium/tagged_burst_to_pdu.h"
GR_SWIG_BLOCK_MAGIC2(iridium, tagged_burst_to_pdu);
%include "iridium/burst_downmix.h"
GR_SWIG_BLOCK_MAGIC2(iridium, burst_downmix);
%include "iridium/pdu_null_sink.h"
GR_SWIG_BLOCK_MAGIC2(iridium, pdu_null_sink);
%include "iridium/iridium_qpsk_demod_cpp.h"
GR_SWIG_BLOCK_MAGIC2(iridium, iridium_qpsk_demod_cpp);
%include "iridium/pdu_round_robin.h"
GR_SWIG_BLOCK_MAGIC2(iridium, pdu_round_robin);
