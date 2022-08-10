/* -*- c++ -*- */

#define FUZZER_API

%include "gnuradio.i"			// the common stuff

//load generated python docstrings
%include "fuzzer_swig_doc.i"

%{
#include "fuzzer/packet_insert.h"
%}


%include "fuzzer/packet_insert.h"
GR_SWIG_BLOCK_MAGIC2(fuzzer, packet_insert);
