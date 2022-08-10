/* -*- c++ -*- */

#define NRSC5_API

%include "gnuradio.i"           // the common stuff

//load generated python docstrings
%include "nrsc5_swig_doc.i"

%{
#include "nrsc5/hdc_encoder.h"
#include "nrsc5/l1_fm_encoder.h"
#include "nrsc5/l1_am_encoder.h"
#include "nrsc5/l2_encoder.h"
#include "nrsc5/psd_encoder.h"
#include "nrsc5/sis_encoder.h"
%}

%include "nrsc5/hdc_encoder.h"
GR_SWIG_BLOCK_MAGIC2(nrsc5, hdc_encoder);
%include "nrsc5/l1_fm_encoder.h"
GR_SWIG_BLOCK_MAGIC2(nrsc5, l1_fm_encoder);
%include "nrsc5/l1_am_encoder.h"
GR_SWIG_BLOCK_MAGIC2(nrsc5, l1_am_encoder);
%include "nrsc5/l2_encoder.h"
GR_SWIG_BLOCK_MAGIC2(nrsc5, l2_encoder);
%include "nrsc5/psd_encoder.h"
GR_SWIG_BLOCK_MAGIC2(nrsc5, psd_encoder);
%include "nrsc5/sis_encoder.h"
GR_SWIG_BLOCK_MAGIC2(nrsc5, sis_encoder);
