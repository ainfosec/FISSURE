/* -*- c++ -*- */

#define AINFOSEC_API

%include "gnuradio.i"           // the common stuff

//load generated python docstrings
%include "ainfosec_swig_doc.i"

%{
#include "ainfosec/wideband_detector1.h"
%}

%include "ainfosec/wideband_detector1.h"
GR_SWIG_BLOCK_MAGIC2(ainfosec, wideband_detector1);
