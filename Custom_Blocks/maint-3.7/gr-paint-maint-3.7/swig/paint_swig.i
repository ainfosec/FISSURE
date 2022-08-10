/* -*- c++ -*- */

#define PAINT_API

%include "gnuradio.i"			// the common stuff

//load generated python docstrings
%include "paint_swig_doc.i"

%{
#include "paint/paint_bc.h"
#include "paint/paint_config.h"
%}


%include "paint/paint_bc.h"
%include "paint/paint_config.h"
GR_SWIG_BLOCK_MAGIC2(paint, paint_bc);
