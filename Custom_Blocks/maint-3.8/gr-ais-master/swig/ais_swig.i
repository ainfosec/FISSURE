/* -*- c++ -*- */

#define AIS_API

%include "gnuradio.i"			// the common stuff

%{
#include "ais/freqest.h"
#include "ais/invert.h"
#include "ais/pdu_to_nmea.h"
#include "ais/msk_timing_recovery_cc.h"
#include "ais/corr_est_cc.h"
%}


%include "ais/freqest.h"
GR_SWIG_BLOCK_MAGIC2(ais, freqest);
%include "ais/invert.h"
GR_SWIG_BLOCK_MAGIC2(ais, invert);
%include "ais/msk_timing_recovery_cc.h"
GR_SWIG_BLOCK_MAGIC2(ais, msk_timing_recovery_cc);
%include "ais/corr_est_cc.h"
GR_SWIG_BLOCK_MAGIC2(ais, corr_est_cc);

%include "ais/pdu_to_nmea.h"
GR_SWIG_BLOCK_MAGIC2(ais, pdu_to_nmea);
