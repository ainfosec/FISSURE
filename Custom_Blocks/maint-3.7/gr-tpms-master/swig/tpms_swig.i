/* -*- c++ -*- */

#define TPMS_API

%include "gnuradio.i"			// the common stuff

//load generated python docstrings
%include "tpms_swig_doc.i"

%{
#include "tpms/ask_env.h"
#include "tpms/fixed_length_frame_sink.h"
#include "tpms/burst_detector.h"
%}


%include "tpms/ask_env.h"
GR_SWIG_BLOCK_MAGIC2(tpms, ask_env);
%include "tpms/fixed_length_frame_sink.h"
GR_SWIG_BLOCK_MAGIC2(tpms, fixed_length_frame_sink);
%include "tpms/burst_detector.h"
GR_SWIG_BLOCK_MAGIC2(tpms, burst_detector);
