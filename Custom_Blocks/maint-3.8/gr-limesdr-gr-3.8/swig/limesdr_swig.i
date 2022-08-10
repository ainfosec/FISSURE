/* -*- c++ -*- */

#define LIMESDR_API

%include "gnuradio.i"           // the common stuff

//load generated python docstrings
%include "limesdr_swig_doc.i"



%{
#include "limesdr/source.h"
#include "limesdr/sink.h"
%}
%include "limesdr/source.h"
%include "limesdr/sink.h"

#ifdef ENABLE_RFE
%{
#include "limesdr/rfe.h"
%}
%include "limesdr/rfe.h"
#endif

GR_SWIG_BLOCK_MAGIC2(limesdr, source);
GR_SWIG_BLOCK_MAGIC2(limesdr, sink);
