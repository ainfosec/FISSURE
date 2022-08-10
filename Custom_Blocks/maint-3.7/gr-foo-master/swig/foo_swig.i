#define FOO_API

%include "gnuradio.i"

//load generated python docstrings
%include "foo_swig_doc.i"

%{
#include "foo/burst_tagger.h"
#include "foo/packet_dropper.h"
#include "foo/packet_pad.h"
#include "foo/packet_pad2.h"
#include "foo/periodic_msg_source.h"
#include "foo/random_periodic_msg_source.h"
#include "foo/rtt_measure.h"
#include "foo/wireshark_connector.h"
%}


%include "foo/burst_tagger.h"
%include "foo/packet_dropper.h"
%include "foo/packet_pad.h"
%include "foo/packet_pad2.h"
%include "foo/periodic_msg_source.h"
%include "foo/random_periodic_msg_source.h"
%include "foo/rtt_measure.h"
%include "foo/wireshark_connector.h"

GR_SWIG_BLOCK_MAGIC2(foo, burst_tagger);
GR_SWIG_BLOCK_MAGIC2(foo, packet_dropper);
GR_SWIG_BLOCK_MAGIC2(foo, packet_pad);
GR_SWIG_BLOCK_MAGIC2(foo, packet_pad2);
GR_SWIG_BLOCK_MAGIC2(foo, periodic_msg_source);
GR_SWIG_BLOCK_MAGIC2(foo, random_periodic_msg_source);
GR_SWIG_BLOCK_MAGIC2(foo, rtt_measure);
GR_SWIG_BLOCK_MAGIC2(foo, wireshark_connector);
