#define RDS_API

%include <gnuradio.i>
%include "rds_swig_doc.i"

%{
#include "rds/decoder.h"
#include "rds/encoder.h"
#include "rds/parser.h"
%}

%include "rds/decoder.h"
%include "rds/encoder.h"
%include "rds/parser.h"

GR_SWIG_BLOCK_MAGIC2(rds, decoder);
GR_SWIG_BLOCK_MAGIC2(rds, encoder);
GR_SWIG_BLOCK_MAGIC2(rds, parser);
