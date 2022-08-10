/* -*- c++ -*- */

#define LIMESDR_API

%include "gnuradio.i"			// the common stuff

//load generated python docstrings
%include "limesdr_swig_doc.i"

%{
#include "limesdr/source.h"
#include "limesdr/sink.h"
%}

%include "limesdr/source.h"
GR_SWIG_BLOCK_MAGIC2(limesdr, source);

%include "limesdr/sink.h"
GR_SWIG_BLOCK_MAGIC2(limesdr, sink);

