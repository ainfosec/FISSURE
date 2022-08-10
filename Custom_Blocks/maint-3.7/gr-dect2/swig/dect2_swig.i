/* -*- c++ -*- */

#define DECT2_API

%include "gnuradio.i"			// the common stuff

//load generated python docstrings
%include "dect2_swig_doc.i"

%{
#include "dect2/phase_diff.h"
#include "dect2/packet_decoder.h"
#include "dect2/packet_receiver.h"
%}

%include "dect2/phase_diff.h"
GR_SWIG_BLOCK_MAGIC2(dect2, phase_diff);


%include "dect2/packet_decoder.h"
GR_SWIG_BLOCK_MAGIC2(dect2, packet_decoder);
%include "dect2/packet_receiver.h"
GR_SWIG_BLOCK_MAGIC2(dect2, packet_receiver);
