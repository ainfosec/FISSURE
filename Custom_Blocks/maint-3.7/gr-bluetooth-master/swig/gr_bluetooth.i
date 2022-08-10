/* -*- c++ -*- */

#define GR_BLUETOOTH_API

%include "gnuradio.i"			// the common stuff

#ifndef GR_SWIG_BLOCK_MAGIC2
%define GR_SWIG_BLOCK_MAGIC2(PKG, BASE_NAME)
%template(BASE_NAME ## _sptr) boost::shared_ptr<gr:: ## PKG ## :: ## BASE_NAME>;
%pythoncode %{
BASE_NAME ## _sptr.__repr__ = lambda self: "<gr_block %s (%d)>" % (self.name(), self.unique_id())
BASE_NAME = BASE_NAME.make;
%}
%enddef
#endif

//load generated python docstrings
%include "gr_bluetooth_doc.i"

%{
#include "gr_bluetooth/packet.h"
#include "gr_bluetooth/piconet.h"
#include "gr_bluetooth/multi_block.h"
#include "gr_bluetooth/multi_hopper.h"
#include "gr_bluetooth/multi_LAP.h"
#include "gr_bluetooth/multi_sniffer.h"
#include "gr_bluetooth/multi_UAP.h"
%}

%include "gr_bluetooth/packet.h"
%include "gr_bluetooth/piconet.h"

%include "gr_bluetooth/multi_block.h"

%include "gr_bluetooth/multi_hopper.h"
GR_SWIG_BLOCK_MAGIC2(bluetooth, multi_hopper);

%include "gr_bluetooth/multi_LAP.h"
GR_SWIG_BLOCK_MAGIC2(bluetooth, multi_LAP);

%include "gr_bluetooth/multi_sniffer.h"
GR_SWIG_BLOCK_MAGIC2(bluetooth, multi_sniffer);

%include "gr_bluetooth/multi_UAP.h"
GR_SWIG_BLOCK_MAGIC2(bluetooth, multi_UAP);


