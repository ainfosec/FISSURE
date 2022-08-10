/* -*- c++ -*- */

#define AIS_API

%include "gnuradio.i"			// the common stuff

//load generated python docstrings
%include "ais_swig_doc.i"

%{
#include "ais/freqest.h"
#include "ais/invert.h"
#include "ais/parse.h"
#include "ais/unstuff.h"
%}


%include "ais/freqest.h"
GR_SWIG_BLOCK_MAGIC2(ais, freqest);
%include "ais/invert.h"
GR_SWIG_BLOCK_MAGIC2(ais, invert);
%include "ais/parse.h"
GR_SWIG_BLOCK_MAGIC2(ais, parse);
%include "ais/unstuff.h"
GR_SWIG_BLOCK_MAGIC2(ais, unstuff);
