/* -*- c++ -*- */

#define ZWAVE_API

%include "gnuradio.i"			// the common stuff

//load generated python docstrings
%include "Zwave_swig_doc.i"

%{
#include "Zwave/packet_sink.h"
#include "Zwave/preamble.h"
#include "Zwave/packet_sink_9_6.h"
%}


%include "Zwave/packet_sink.h"
GR_SWIG_BLOCK_MAGIC2(Zwave, packet_sink);
%include "Zwave/preamble.h"
GR_SWIG_BLOCK_MAGIC2(Zwave, preamble);

%include "Zwave/packet_sink_9_6.h"
GR_SWIG_BLOCK_MAGIC2(Zwave, packet_sink_9_6);
