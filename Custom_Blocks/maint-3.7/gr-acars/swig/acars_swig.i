/* -*- c++ -*- */

#define ACARS_API

%include "gnuradio.i"			// the common stuff

//load generated python docstrings
%include "acars_swig_doc.i"

%{
#include "acars/acars.h"
%}


%include "acars/acars.h"
GR_SWIG_BLOCK_MAGIC2(acars, acars);
