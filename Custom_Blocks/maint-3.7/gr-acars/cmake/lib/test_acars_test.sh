#!/bin/sh
export VOLK_GENERIC=1
export GR_DONT_LOAD_PREFS=1
export srcdir=/home/jmfriedt/sdr/gr-acars/lib
export PATH=/home/jmfriedt/sdr/gr-acars/cmake/lib:$PATH
export LD_LIBRARY_PATH=/home/jmfriedt/sdr/gr-acars/cmake/lib:$LD_LIBRARY_PATH
export PYTHONPATH=$PYTHONPATH
test-acars 
